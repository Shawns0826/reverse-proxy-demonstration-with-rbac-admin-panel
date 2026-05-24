package com.example.vulnerable_app

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.ProgressBar
import android.widget.Toast
import androidx.fragment.app.FragmentActivity
import java.util.concurrent.Executors

class LoginActivity : FragmentActivity() {

    private val executor = Executors.newSingleThreadExecutor()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_login)

        if (AuthSession.isLoggedIn()) {
            goMain()
            return
        }

        val username = findViewById<EditText>(R.id.edit_username)
        val password = findViewById<EditText>(R.id.edit_password)
        val button = findViewById<Button>(R.id.button_login)
        val progress = findViewById<ProgressBar>(R.id.progress)

        button.setOnClickListener {
            val u = username.text.toString().trim()
            val p = password.text.toString()
            if (u.isEmpty() || p.isEmpty()) {
                Toast.makeText(this, R.string.login_failed, Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            button.isEnabled = false
            progress.visibility = View.VISIBLE
            executor.execute {
                val err = ApiClient.login(applicationContext, u, p)
                runOnUiThread {
                    progress.visibility = View.GONE
                    button.isEnabled = true
                    if (err == null) {
                        goMain()
                    } else {
                        Toast.makeText(this, err, Toast.LENGTH_LONG).show()
                    }
                }
            }
        }
    }

    private fun goMain() {
        startActivity(Intent(this, MainActivity::class.java))
        finish()
    }
}
