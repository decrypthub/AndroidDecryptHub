package com.adh.manager

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.LayoutInflater
import android.view.ViewGroup
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.adh.manager.databinding.ActivityScopeBinding
import com.adh.manager.databinding.ItemAppBinding
import com.google.android.material.snackbar.Snackbar

data class AppRow(
    val packageName: String,
    val label: String,
    val isSystem: Boolean,
    val info: ApplicationInfo,
    var checked: Boolean,
)

class ScopeActivity : AppCompatActivity() {
    private lateinit var binding: ActivityScopeBinding
    private val selected = linkedSetOf<String>()
    private var allRows: List<AppRow> = emptyList()
    private lateinit var adapter: AppAdapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityScopeBinding.inflate(layoutInflater)
        setContentView(binding.root)
        binding.toolbar.setNavigationOnClickListener { finish() }

        selected.addAll(ScopeStore.load().packages)
        adapter = AppAdapter { row, checked ->
            row.checked = checked
            if (checked) selected.add(row.packageName) else selected.remove(row.packageName)
        }
        binding.list.layoutManager = LinearLayoutManager(this)
        binding.list.adapter = adapter

        binding.showSystem.setOnCheckedChangeListener { _, _ -> applyFilter() }
        binding.search.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) = applyFilter()
        })
        binding.refresh.setOnRefreshListener { loadApps() }
        binding.btnSave.setOnClickListener { save() }

        loadApps()
    }

    private fun loadApps() {
        binding.refresh.isRefreshing = true
        Thread {
            val pm = packageManager
            val apps = pm.getInstalledApplications(PackageManager.GET_META_DATA)
            val rows = apps
                .filter { it.packageName != ScopeStore.MANAGER_PKG }
                .map { ai ->
                    val label = try {
                        pm.getApplicationLabel(ai).toString()
                    } catch (_: Exception) {
                        ai.packageName
                    }
                    val system = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0
                    AppRow(ai.packageName, label, system, ai, selected.contains(ai.packageName))
                }
                .sortedWith(compareByDescending<AppRow> { it.checked }.thenBy { it.label.lowercase() })
            runOnUiThread {
                allRows = rows
                applyFilter()
                binding.refresh.isRefreshing = false
            }
        }.start()
    }

    private fun applyFilter() {
        val q = binding.search.text?.toString()?.trim()?.lowercase().orEmpty()
        val showSys = binding.showSystem.isChecked
        adapter.submit(
            allRows.filter { row ->
                (showSys || !row.isSystem) &&
                    (q.isEmpty() || row.label.lowercase().contains(q) || row.packageName.lowercase().contains(q))
            },
        )
    }

    private fun save() {
        val scope = ScopeStore.Scope(selected.toMutableSet())
        val result = ScopeStore.save(scope)
        if (result.isSuccess) {
            Snackbar.make(binding.root, R.string.saved, Snackbar.LENGTH_LONG).show()
        } else {
            Toast.makeText(
                this,
                getString(R.string.save_failed, result.exceptionOrNull()?.message ?: "unknown"),
                Toast.LENGTH_LONG,
            ).show()
        }
    }
}

class AppAdapter(
    private val onToggle: (AppRow, Boolean) -> Unit,
) : RecyclerView.Adapter<AppAdapter.VH>() {
    private val items = mutableListOf<AppRow>()

    fun submit(rows: List<AppRow>) {
        items.clear()
        items.addAll(rows)
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
        val b = ItemAppBinding.inflate(LayoutInflater.from(parent.context), parent, false)
        return VH(b)
    }

    override fun getItemCount() = items.size

    override fun onBindViewHolder(holder: VH, position: Int) = holder.bind(items[position])

    inner class VH(private val b: ItemAppBinding) : RecyclerView.ViewHolder(b.root) {
        fun bind(row: AppRow) {
            b.label.text = row.label
            b.pkg.text = row.packageName
            b.icon.setImageDrawable(row.info.loadIcon(b.root.context.packageManager))
            b.check.setOnCheckedChangeListener(null)
            b.check.isChecked = row.checked
            b.check.setOnCheckedChangeListener { _, checked -> onToggle(row, checked) }
            b.root.setOnClickListener { b.check.isChecked = !b.check.isChecked }
        }
    }
}
