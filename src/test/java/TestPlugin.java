import com.formdev.flatlaf.extras.FlatUIDefaultsInspector;

import java.lang.reflect.Method;

public class TestPlugin {
    public static void main(String[] args) {
        //Legacy extension support has been removed from Burp, so this will no longer work.
//        try {
//            Method main = Class.forName("burp.StartBurp").getMethod("main", String[].class);
//            main.invoke(null, (Object) args);
//        }catch (Exception e){
//            System.err.println("Cannot start burp. Check the burp jar is correctly included in the classpath.");
//        }
    }
}