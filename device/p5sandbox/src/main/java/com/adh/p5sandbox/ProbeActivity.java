package com.adh.p5sandbox;
import android.app.Activity;
import android.os.Bundle;
import android.content.Intent;
import android.view.WindowManager;
import android.widget.TextView;

/** Own visible fixture only. Avoid ROM background freezing without changing system policy. */
public final class ProbeActivity extends Activity {
    public void onCreate(Bundle saved){super.onCreate(saved);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        setShowWhenLocked(true);setTurnScreenOn(true);
        TextView label=new TextView(this);label.setText("ADH isolated Zygisk test");label.setTextSize(22);label.setGravity(android.view.Gravity.CENTER);setContentView(label);
        startForegroundService(new Intent(this,ProbeService.class).putExtra("zygiskOnly",true));
    }
}
