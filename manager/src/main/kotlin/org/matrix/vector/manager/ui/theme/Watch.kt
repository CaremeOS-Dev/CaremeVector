package org.matrix.vector.manager.ui.theme

import androidx.compose.runtime.Composable
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.ui.platform.LocalConfiguration

/**
 * True when the app is on a very small screen (a smartwatch). The watch has a weak CPU and a tiny
 * round display, so the adaptive "watch mode" trims animated flourishes and the startup prefetch
 * burst that otherwise stall the first frames. Layout stays on the adaptive NavigationSuiteScaffold,
 * which already picks a compact container at this width.
 *
 * 320dp is the XTC watch (320x360 @ 320dpi). The threshold is a little above it so a 320dp screen
 * qualifies but a small phone (>=360dp) does not.
 */
@Composable
@ReadOnlyComposable
fun isWatch(): Boolean {
    val config = LocalConfiguration.current
    return config.smallestScreenWidthDp <= 340
}
