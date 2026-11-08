package io.github.revocx35.flagsecure

import android.graphics.drawable.Icon
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * Quick-settings tile that toggles the FLAG_SECURE bypass from the notification shade.
 *
 * - Active   = bypass on (screenshots work); the pause flag is absent and the agent is injected.
 * - Inactive = FLAG_SECURE enforced; pause flag present or not injected this boot.
 *
 * Tapping flips it: when active it re-enables FLAG_SECURE (instant flag), when inactive it removes
 * the flag and injects if needed (a few seconds the first time per boot). All root work runs off the
 * main thread via [Injector]; the tile shows a brief unavailable state while working.
 */
class FlagSecureTileService : TileService() {

    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())

    override fun onStartListening() {
        refresh()
    }

    override fun onClick() {
        val tile = qsTile ?: return
        tile.state = Tile.STATE_UNAVAILABLE
        tile.updateTile()
        scope.launch {
            if (Injector.isActive()) {
                Injector.reEnable()
            } else {
                Injector.apply(this@FlagSecureTileService)
            }
            refresh()
        }
    }

    private fun refresh() {
        scope.launch {
            val tile = qsTile ?: return@launch
            val rooted = Injector.hasRoot()
            val active = rooted && Injector.isActive()
            tile.state = when {
                !rooted -> Tile.STATE_UNAVAILABLE
                active -> Tile.STATE_ACTIVE
                else -> Tile.STATE_INACTIVE
            }
            tile.label = "FLAG_SECURE off"
            tile.icon = Icon.createWithResource(this@FlagSecureTileService, R.drawable.ic_tile)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                tile.subtitle = when {
                    !rooted -> "No root"
                    active -> "Screenshots on"
                    else -> "Tap to allow"
                }
            }
            tile.updateTile()
        }
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }
}
