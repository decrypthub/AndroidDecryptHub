package com.adh.manager.ui.scope

import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.adh.manager.R
import com.adh.manager.data.ScopeRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

/** Observation/revocation only. No fixed family editor and no silent Host plan creation. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HookConfigScreen(packageName:String,draft:ScopeDraft,onBack:()->Unit,repository:ScopeRepository){
    var state by remember(packageName){mutableStateOf<JSONObject?>(null)}
    var message by remember(packageName){mutableStateOf("")}
    var busy by remember{mutableStateOf(false)}
    val coroutine=rememberCoroutineScope()
    fun refresh(){coroutine.launch{busy=true;message="";val result=withContext(Dispatchers.IO){runCatching{repository.hookPlanState(packageName)?.let{JSONObject(it)}}};state=result.getOrNull();if(result.isFailure)message=result.exceptionOrNull()?.message.orEmpty();busy=false}}
    LaunchedEffect(packageName){refresh()}
    Scaffold(topBar={TopAppBar(title={Text(stringResource(R.string.host_plan_title))},navigationIcon={IconButton(onClick=onBack){Icon(Icons.AutoMirrored.Rounded.ArrowBack,contentDescription=stringResource(R.string.back))}})}){padding->
        Column(Modifier.fillMaxSize().padding(padding).padding(20.dp),verticalArrangement=Arrangement.spacedBy(12.dp)){
            Text(packageName,style=MaterialTheme.typography.titleMedium)
            Text(stringResource(R.string.host_plan_guidance))
            Text(stringResource(R.string.host_plan_legacy)+(draft.families[packageName]?.toString()?:"default"),style=MaterialTheme.typography.bodySmall)
            val snapshot=state;val entry=snapshot?.optJSONObject("entry")
            if(snapshot==null)Text(stringResource(R.string.host_plan_unavailable))
            else if(entry==null)Text(stringResource(R.string.host_plan_no_cache))
            else {Text(entry.optString("state"));Text(entry.optString("digest"),style=MaterialTheme.typography.bodySmall);Text("TTL: "+entry.optLong("expiresAt"));Text(stringResource(R.string.host_plan_not_installed))}
            if(message.isNotBlank())Text(message,color=MaterialTheme.colorScheme.error)
            Button(onClick={refresh()},enabled=!busy){Text(stringResource(R.string.host_plan_refresh))}
            OutlinedButton(enabled=!busy&&entry!=null&&entry.optString("state")!="revoked",onClick={
                val observed=state?:return@OutlinedButton;val selected=observed.optJSONObject("entry")?:return@OutlinedButton
                coroutine.launch{busy=true;val result=withContext(Dispatchers.IO){repository.revokeHookPlan(packageName,selected.getString("deploymentId"),observed.getLong("cacheRevision"),observed.getLong("stateRevision"))};busy=false;message=if(result.isSuccess)"" else result.exceptionOrNull()?.message.orEmpty();if(result.isSuccess)refresh()}
            }){Text(stringResource(R.string.host_plan_revoke))}
            Text(stringResource(R.string.host_plan_revoke_note),style=MaterialTheme.typography.bodySmall)
        }
    }
}
