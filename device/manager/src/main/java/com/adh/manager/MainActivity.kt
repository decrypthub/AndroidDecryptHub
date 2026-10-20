package com.adh.manager

import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import com.adh.core.ScopeConfig
import com.adh.manager.data.ScopeWriter
import kotlinx.coroutines.launch
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.adh.manager.data.DaemonScopeRepository
import com.adh.manager.data.HostWebUiRepository
import com.adh.manager.data.ScopeRepository
import com.adh.manager.data.WebUiRepository
import com.adh.manager.ui.Routes
import com.adh.manager.ui.cert.CaCertScreen
import com.adh.manager.ui.home.HomeScreen
import com.adh.manager.ui.scope.HookConfigScreen
import com.adh.manager.ui.scope.ScopeDraft
import com.adh.manager.ui.scope.ScopeScreen
import com.adh.manager.ui.theme.AdhTheme

class MainActivity : ComponentActivity() {
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
    NavHost(navController = nav, startDestination = Routes.HOME) {
        composable(Routes.HOME) {
            HomeScreen(
                repository = repo,
                webUiRepository = webUiRepository,
                onOpenScope = { nav.navigate(Routes.SCOPE) },
                onOpenCerts = { nav.navigate(Routes.CERTS) },
            )
        }
        composable(Routes.CERTS) {
            CaCertScreen(
                repository = repo,
                onBack = { nav.popBackStack() },
            )
        }
        composable(Routes.SCOPE) {
            ScopeScreen(
                repository = repo,
                draft = draft,
                onBack = { nav.popBackStack() },
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
