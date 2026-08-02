package app.satoshivault.signer;

import android.os.Bundle;
import android.view.WindowManager;

import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {

    @Override
    public void onCreate(Bundle savedInstanceState) {
        // FLAG_SECURE blocks screenshots, screen recorders, MediaProjection and
        // the recents-list thumbnail for every screen of the Signer. The seed
        // grid and the PSBT review screen are the whole secret; a screen-capture
        // trojan or a shoulder-surfed recents snapshot must not see them.
        // Set before super.onCreate() so the very first frame is already covered.
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
        super.onCreate(savedInstanceState);
    }
}
