package io.github.revocx35.flagsecure

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.MaterialTheme.colorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            val ctx = LocalContext.current
            val colors = remember {
                runCatching { dynamicLightColorScheme(ctx) }.getOrElse { dynamicDarkColorScheme(ctx) }
            }
            MaterialTheme(colorScheme = colors) {
                Scaffold { inner -> ScreenContent(Modifier.padding(inner)) }
            }
        }
    }
}

private sealed interface UiState {
    data object Idle : UiState
    data object Working : UiState
    data class Done(val result: Injector.Result) : UiState
}

@Composable
private fun ScreenContent(modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var rooted by remember { mutableStateOf<Boolean?>(null) }
    var state by remember { mutableStateOf<UiState>(UiState.Idle) }

    LaunchedEffect(Unit) { rooted = Injector.hasRoot() }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(
            text = "Disable FLAG_SECURE",
            style = MaterialTheme.typography.headlineSmall,
        )
        Text(
            text = "Injects a Frida agent into system_server so the window manager ignores " +
                "FLAG_SECURE. Screenshots and screen recording then work in apps that block them. " +
                "Turning it off fully removes the hooks (no leftover slowdown); turning it on " +
                "injects again (a few seconds). No reboot either way. There's also a " +
                "\"FLAG_SECURE off\" Quick Settings tile — add it from the shade editor.",
            style = MaterialTheme.typography.bodyMedium,
        )

        Card(
            colors = CardDefaults.cardColors(containerColor = colorScheme.errorContainer),
        ) {
            Text(
                text = "Root required. This modifies the running system. It does not defeat " +
                    "hardware DRM (Widevine L1), so paid-video apps stay black. Use only on your " +
                    "own device.",
                style = MaterialTheme.typography.bodySmall,
                color = colorScheme.onErrorContainer,
                modifier = Modifier.padding(14.dp),
            )
        }

        Text(
            text = when (rooted) {
                null -> "Checking for root…"
                true -> "Root access: granted"
                false -> "Root access: not granted — grant su to this app first"
            },
            style = MaterialTheme.typography.bodyMedium,
        )

        Button(
            onClick = {
                state = UiState.Working
                scope.launch {
                    val r = Injector.apply(context)
                    rooted = true
                    state = UiState.Done(r)
                }
            },
            enabled = state !is UiState.Working && rooted != false,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(if (state is UiState.Working) "Injecting…" else "Disable FLAG_SECURE now")
        }

        OutlinedButton(
            onClick = {
                state = UiState.Working
                scope.launch {
                    val r = Injector.reEnable()
                    state = UiState.Done(r)
                }
            },
            enabled = state !is UiState.Working && rooted != false,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Re-enable FLAG_SECURE (instant)")
        }

        when (val s = state) {
            is UiState.Working -> CircularProgressIndicator()
            is UiState.Done -> ResultView(s.result)
            UiState.Idle -> Unit
        }
    }
}

@Composable
private fun ResultView(result: Injector.Result) {
    Card(
        colors = CardDefaults.cardColors(
            containerColor = if (result.success) colorScheme.primaryContainer else colorScheme.surfaceVariant,
        ),
    ) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                text = result.summary,
                style = MaterialTheme.typography.titleSmall,
                color = if (result.success) colorScheme.onPrimaryContainer else colorScheme.onSurfaceVariant,
            )
            result.hooks.forEach { hook ->
                Text(
                    text = (if (hook.applied) "✓ " else "– ") + hook.target,
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                )
            }
            if (result.log.isNotBlank()) {
                Text(
                    text = result.log,
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    color = colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}
