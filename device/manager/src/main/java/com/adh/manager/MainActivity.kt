package com.adh.manager

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.adh.manager.data.DaemonScopeRepository
import com.adh.manager.data.HostWebUiRepository
import com.adh.manager.data.ScopeRepository
import com.adh.manager.data.WebUiRepository
import com.adh.manager.ui.Routes
import com.adh.manager.ui.home.HomeScreen
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
    NavHost(navController = nav, startDestination = Routes.HOME) {
        composable(Routes.HOME) {
            HomeScreen(
                repository = repo,
                webUiRepository = webUiRepository,
                onOpenScope = { nav.navigate(Routes.SCOPE) },
            )
        }
        composable(Routes.SCOPE) {
            ScopeScreen(
                repository = repo,
                onBack = { nav.popBackStack() },
            )
        }
    }
}
