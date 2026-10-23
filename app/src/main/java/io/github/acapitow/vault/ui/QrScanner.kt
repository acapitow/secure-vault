@file:OptIn(ExperimentalMaterial3Api::class)

package io.github.acapitow.vault.ui

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.google.zxing.BinaryBitmap
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.ReaderException
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Lecture d'un QR code TOTP. Les images restent en mémoire, analysées sur
 * place par ZXing : rien n'est enregistré ni envoyé (l'application n'a pas
 * la permission INTERNET). La permission caméra n'est demandée qu'ici.
 */
@Composable
fun QrScanner(onResult: (String) -> Unit, onCancel: () -> Unit) {
    val context = LocalContext.current
    var granted by remember {
        mutableStateOf(ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED)
    }
    var denied by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { ok ->
        granted = ok
        denied = !ok
    }
    LaunchedEffect(Unit) { if (!granted) launcher.launch(Manifest.permission.CAMERA) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Scanner un QR code") },
                actions = { TextButton(onClick = onCancel) { Text("Annuler") } },
            )
        },
    ) { padding ->
        val failure = error
        when {
            failure != null -> Column(Modifier.padding(padding).padding(16.dp)) {
                Text("La caméra n'a pas pu démarrer. Tu peux saisir la clé secrète à la main.")
                Text("Détail : $failure", style = MaterialTheme.typography.bodySmall)
            }
            granted -> CameraPreview(Modifier.padding(padding).fillMaxSize(), onResult) { error = it }
            denied -> Column(Modifier.padding(padding).padding(16.dp)) {
                Text("Accès à la caméra refusé. Tu peux saisir la clé secrète à la main.")
            }
        }
    }
}

/** Type et message d'une erreur (jamais de secret : uniquement caméra / décodage d'image). */
private fun describe(e: Throwable): String {
    val root = generateSequence(e) { it.cause }.last()
    return "${e.javaClass.name}: ${e.message}" + if (root !== e) " ← ${root.javaClass.name}: ${root.message}" else ""
}

@Composable
private fun CameraPreview(modifier: Modifier, onResult: (String) -> Unit, onError: (String) -> Unit) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val currentOnResult by rememberUpdatedState(onResult)
    val currentOnError by rememberUpdatedState(onError)
    val previewView = remember { PreviewView(context) }

    DisposableEffect(lifecycleOwner) {
        val executor = Executors.newSingleThreadExecutor()
        val mainExecutor = ContextCompat.getMainExecutor(context)
        val providerFuture = ProcessCameraProvider.getInstance(context)
        val done = AtomicBoolean(false)
        var disposed = false

        // Toute erreur (initialisation de CameraX, caméra absente ou occupée, image
        // inattendue) devient un message au lieu de faire planter l'application.
        fun fail(e: Throwable) {
            if (done.compareAndSet(false, true)) mainExecutor.execute { if (!disposed) currentOnError(describe(e)) }
        }

        providerFuture.addListener({
            if (disposed) return@addListener
            try {
                val provider = providerFuture.get()
                val preview = Preview.Builder().build()
                preview.setSurfaceProvider(previewView.surfaceProvider)
                val analysis = ImageAnalysis.Builder()
                    .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                    .build()
                analysis.setAnalyzer(
                    executor,
                    QrAnalyzer(
                        onQr = { text ->
                            // Un seul résultat, remis sur le thread principal.
                            if (done.compareAndSet(false, true)) mainExecutor.execute { if (!disposed) currentOnResult(text) }
                        },
                        onError = ::fail,
                    ),
                )
                provider.unbindAll()
                provider.bindToLifecycle(lifecycleOwner, CameraSelector.DEFAULT_BACK_CAMERA, preview, analysis)
            } catch (e: Exception) {
                fail(e)
            }
        }, mainExecutor)

        onDispose {
            disposed = true
            if (providerFuture.isDone) runCatching { providerFuture.get().unbindAll() }
            executor.shutdown()
        }
    }

    AndroidView(factory = { previewView }, modifier = modifier)
}

/** Décode la luminance (plan Y) de chaque image avec ZXing. */
private class QrAnalyzer(
    private val onQr: (String) -> Unit,
    private val onError: (Throwable) -> Unit,
) : ImageAnalysis.Analyzer {

    private val reader = QRCodeReader()

    override fun analyze(image: ImageProxy) {
        try {
            val plane = image.planes[0]
            val buffer = plane.buffer.duplicate().apply { rewind() }
            val width = image.width
            val height = image.height
            // Copie ligne par ligne : le tampon peut avoir un pas (rowStride) supérieur
            // à la largeur, et sa dernière ligne être plus courte.
            val luminance = ByteArray(width * height)
            for (row in 0 until height) {
                buffer.position(row * plane.rowStride)
                buffer.get(luminance, row * width, width)
            }
            val source = PlanarYUVLuminanceSource(luminance, width, height, 0, 0, width, height, false)
            onQr(reader.decode(BinaryBitmap(HybridBinarizer(source))).text)
        } catch (_: ReaderException) {
            // Pas de QR code lisible dans cette image : on attend la suivante.
        } catch (e: Exception) {
            onError(e)
        } finally {
            reader.reset()
            image.close()
        }
    }
}
