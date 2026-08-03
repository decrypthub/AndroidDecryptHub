package com.adh.manager

import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.adh.manager.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        binding.btnScope.setOnClickListener {
            startActivity(Intent(this, ScopeActivity::class.java))
        }
    }

    override fun onResume() {
        super.onResume()
        refreshStatus()
    }

    private fun refreshStatus() {
        val moduleOk = ScopeStore.modulePresent()
        binding.moduleStatus.text = getString(if (moduleOk) R.string.module_ok else R.string.module_missing)
        binding.moduleStatus.setTextColor(getColor(if (moduleOk) R.color.ok else R.color.warn))
        val n = ScopeStore.load().packages.size
        binding.scopeCount.text = getString(R.string.scope_count, n)
    }
}
