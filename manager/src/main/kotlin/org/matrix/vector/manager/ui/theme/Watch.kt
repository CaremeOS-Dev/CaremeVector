package org.matrix.vector.manager.ui.theme

import android.content.res.Configuration
import androidx.compose.runtime.Composable
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.ui.platform.LocalConfiguration

/**
 * True when the app is on a very small screen (a smartwatch). The watch has a weak CPU and a tiny
 * display, so the adaptive "watch mode" trims animated flourishes and the startup prefetch burst
 * that otherwise stall the first frames. Layout stays on the adaptive NavigationSuiteScaffold,
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

/**
 * True on a *square* watch. The 320x360 XTC Z9 is square, and the user finds the stock 320dpi
 * rendering cramped; a square watch gets a density reduction (see [watchDensityScale]) so content
 * is larger and less crowded. Round watches keep the stock density — a round bezel already crops
 * the corners, so enlarging further would lose more than it gains.
 */
@Composable
@ReadOnlyComposable
fun isSquareWatch(): Boolean {
    val config = LocalConfiguration.current
    return isWatch() &&
        (config.screenLayout and Configuration.SCREENLAYOUT_ROUND_MASK) !=
            Configuration.SCREENLAYOUT_ROUND_YES
}

/**
 * How much to shrink the density on a square watch. The user measured 125-150dpi as the sweet spot
 * on the 320dpi panel; 0.42 lands at ~134dpi (320 * 0.42), enlarging content and controls so the
 * square face stops feeling cramped.
 */
const val watchDensityScale: Float = 0.42f
