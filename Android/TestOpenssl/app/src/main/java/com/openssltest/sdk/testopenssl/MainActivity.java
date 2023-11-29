package com.openssltest.sdk.testopenssl;

import androidx.appcompat.app.AppCompatActivity;

import android.content.res.AssetManager;
import android.os.Bundle;
import android.widget.TextView;

import com.openssltest.sdk.testopenssl.databinding.ActivityMainBinding;

public class MainActivity extends AppCompatActivity {

    // Used to load the 'testopenssl' library on application startup.
    static {
        System.loadLibrary("testopenssl");
    }

    private ActivityMainBinding binding;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        // Example of a call to a native method
        TextView tv = binding.sampleText;
        tv.setText(stringFromJNI(this.getAssets()));
    }

    /**
     * A native method that is implemented by the 'testopenssl' native library,
     * which is packaged with this application.
     */
    public native String stringFromJNI(AssetManager assets);
}