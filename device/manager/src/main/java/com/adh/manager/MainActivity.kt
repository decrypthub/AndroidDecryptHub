package com.adh.manager

import android.net.Uri
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Apps
import androidx.compose.material.icons.rounded.Home
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.adh.core.ScopeConfig
import com.adh.manager.data.DaemonScopeRepository
import com.adh.manager.data.HostWebUiRepository
import com.adh.manager.data.ScopeRepository
import com.adh.manager.data.ScopeWriter
import com.adh.manager.data.WebUiRepository
import com.adh.manager.ui.Routes
import com.adh.manager.ui.cert.CaCertScreen
import com.adh.manager.ui.home.HomeScreen
import com.adh.manager.ui.scope.HookConfigScreen
import com.adh.manager.ui.scope.ScopeDraft
import com.adh.manager.ui.scope.ScopeScreen
import com.adh.manager.ui.theme.AdhTheme
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        val repository: ScopeRepository = DaemonScopeRepository()
        val webUiRepository: WebUiRepository = HostWebUiRepository()
        setContent {
            AdhTheme {
                AdhApp(repository = repository, webUiRepository = webUiRepository)
            }
        }
    }
}

@Composable
fun AdhApp(repository: ScopeRepository, webUiRepository: WebUiRepository) {
    val nav = rememberNavController()
    val repo = remember { repository }
    val draft = remember { ScopeDraft() }
    val writer = remember { ScopeWriter { repo.save(it) } }
    val scope = rememberCoroutineScope()
    fun currentConfig() = ScopeConfig(
        packages = draft.selected,
        policy = draft.families.filterKeys { draft.selected.contains(it) },
    )
    fun persist() {
        val config = currentConfig()
        draft.dirty = true
        scope.launch {
            val result = writer.submit(config)
            if (result == null) return@launch
            if (result.isSuccess) {
                if (currentConfig() == config) draft.dirty = false
                draft.persistFailed = false
            } else {
                draft.persistFailed = true
            }
        }
    }
    val route = nav.currentBackStackEntryAsState().value?.destination?.route
    val showTabs = route == null || route == Routes.HOME || route == Routes.SCOPE || route == Routes.CERTS
    fun openTab(target: String) {
        nav.navigate(target) {
            popUpTo(nav.graph.findStartDestination().id) { saveState = true }
            launchSingleTop = true
            restoreState = true
        }
    }
    Scaffold(
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
        bottomBar = {
            if (showTabs) {
                NavigationBar {
                    NavigationBarItem(
                        selected = route == null || route == Routes.HOME,
                        onClick = { openTab(Routes.HOME) },
                        icon = { Icon(Icons.Rounded.Home, contentDescription = null) },
                        label = { Text(stringResource(R.string.tab_home)) },
                    )
                    NavigationBarItem(
                        selected = route == Routes.SCOPE,
                        onClick = { openTab(Routes.SCOPE) },
                        icon = { Icon(Icons.Rounded.Apps, contentDescription = null) },
                        label = { Text(stringResource(R.string.tab_apps)) },
                    )
                    NavigationBarItem(
                        selected = route == Routes.CERTS,
                        onClick = { openTab(Routes.CERTS) },
                        icon = { Icon(Icons.Rounded.Security, contentDescription = null) },
                        label = { Text(stringResource(R.string.tab_certs)) },
                    )
                }
            }
        },
    ) { padding ->
    NavHost(
        navController = nav,
        startDestination = Routes.HOME,
        modifier = Modifier.padding(padding),
    ) {
        composable(Routes.HOME) {
            HomeScreen(
                repository = repo,
                webUiRepository = webUiRepository,
            )
        }
        composable(Routes.CERTS) {
            CaCertScreen(repository = repo)
        }
        composable(Routes.SCOPE) {
            ScopeScreen(
                repository = repo,
                draft = draft,
                onOpenHook = { nav.navigate(Routes.hook(it)) },
                onPersist = { persist() },
            )
        }
        composable(
            route = Routes.HOOK,
            arguments = listOf(navArgument("packageName") { type = NavType.StringType }),
        ) { entry ->
            HookConfigScreen(
                packageName = Uri.decode(entry.arguments?.getString("packageName").orEmpty()),
                draft = draft,
                onBack = { nav.popBackStack() },
                onPersist = { persist() },
            )
        }
    }
    }
}
