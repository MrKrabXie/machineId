package com.crab.machine;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;

import org.omg.CORBA.portable.ApplicationException;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.*;
import java.util.regex.Pattern;

@Slf4j
@Data
public abstract class SysUtils {

    public static boolean isSSid(String ssid) {
        boolean isSSid = false;
        if (ssid != null) {
            ssid = ssid.toUpperCase().trim();
            Pattern pattern = Pattern.compile("[A-Z]\\d{8}");
            isSSid = pattern.matcher(ssid).matches();
        }
        return isSSid;
    }


    /**
     * 把 VO 中所有属性为 null 的转为 ""
     *
     * @throws ApplicationException
     */
    public static void nullConverNullString(Object obj) throws ApplicationException {
        if (obj != null) {
            Class classz = obj.getClass();
            // 获取所有该对象的属性值
            Field[] fields = classz.getDeclaredFields();

            // 遍历属性值，取得所有属性为 null 值的
            for (Field field : fields) {
                try {
                    if (field.getType().getName().equals("java.lang.String")) {
                        Method m = classz.getMethod("get" + change(field.getName()));
                        Object name = m.invoke(obj);// 调用该字段的get方法
                        if (name == null) {

                            Method mtd = classz.getMethod("set" + change(field.getName()), String.class);// 取得所需类的方法对象
                            mtd.invoke(obj, "");// 执行相应赋值方法
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    throw new ApplicationException(null, null);
                }
            }
        }
    }

    /**
     * @param src 源字符串
     * @return 字符串，将src的第一个字母转换为大写，src为空时返回null
     */
    public static String change(String src) {
        if (src != null) {
            StringBuffer sb = new StringBuffer(src);
            sb.setCharAt(0, Character.toUpperCase(sb.charAt(0)));
            return sb.toString();
        } else {
            return null;
        }
    }

    /**
     * 运行命令
     *
     * @param cmd  命令
     * @param line 返回第几行结果，0返回所有
     * @return 结果
     */
    public static String runCmdBK(String cmd, int line) {
        Process process;
        Scanner sc = null;
        StringBuffer sb = new StringBuffer();
        try {
            process = Runtime.getRuntime().exec(cmd);
            process.getOutputStream().close();
            sc = new Scanner(process.getInputStream());
            int i = 0;
            while (sc.hasNextLine()) {
                i++;
                String str = sc.nextLine();
                if (line <= 0) {
                    sb.append(str).append("\r\n");
                } else if (i == line) {
                    return str.trim();
                }
            }
            sc.close();
        } catch (Exception e) {


        } finally {
            IoUtils.close(sc);
        }
        return sb.toString();
    }

    /**
     * 执行命令并返回输出
     * @param command 要执行的命令
     * @param timeoutInSeconds 超时时间（秒），如果命令执行时间超过该值，将会被强制结束
     * @return 命令的标准输出
     */
    public static String runCmd(String command, int timeoutInSeconds) {
        StringBuilder output = new StringBuilder();
        Process process = null;

        try {
            // 创建进程构建器
            ProcessBuilder builder = new ProcessBuilder("cmd.exe", "/c", command);
            builder.redirectErrorStream(true); // 合并标准输出和错误流

            // 启动进程
            process = builder.start();

            // 读取进程的输出
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }

            // 等待命令执行完成
            if (!process.waitFor(timeoutInSeconds, java.util.concurrent.TimeUnit.SECONDS)) {
                // 超时强制结束进程
                process.destroy();
                output.append("\nTimeout (" + timeoutInSeconds + " seconds) exceeded. Process terminated.");
            }

        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        } finally {
            if (process != null) {
                process.destroy();
            }
        }

        return output.toString();
    }

    /**
     * 运行cmd命令
     *
     * @param cmd    命令
     * @param substr 关键字
     * @return 包含关键字的行数
     */
    public static String runCmd(String cmd, String substr) {
        Process process;
        Scanner sc = null;
        try {
            process = Runtime.getRuntime().exec(cmd);
            process.getOutputStream().close();
            sc = new Scanner(process.getInputStream());
            while (sc.hasNextLine()) {
                String str = sc.nextLine();
                if (str != null && str.contains(substr)) {
                    return str.trim();
                }
            }
            sc.close();
        } catch (Exception e) {

        } finally {
            IoUtils.close(sc);
        }
        return null;
    }

    /**
     * 不获取目标的 mac地址
     * @return
     */
    public static String getMacAddressBK() {
        StringBuilder sb = new StringBuilder();
        try {
            Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces();
            while (en.hasMoreElements()) {
                NetworkInterface iface = en.nextElement();
                List<InterfaceAddress> addrs = iface.getInterfaceAddresses();
                for (InterfaceAddress addr : addrs) {
                    InetAddress ip = addr.getAddress();
                    if (!ip.isLinkLocalAddress()) {//只获取本地的
                        byte[] mac = iface.getHardwareAddress();
                        if (mac != null) {
                            sb.delete(0, sb.length());
                            for (int i = 0; i < mac.length; i++) {
                                sb.append(String.format("%02X%s", mac[i], (i < mac.length - 1) ? "-" : ""));
                            }
                            return sb.toString(); // 找到本机 MAC 地址后立即返回
                        }
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null; // 如果没有找到 MAC 地址，则返回 null
    }


    /**
     * 不获取目标的 mac地址
     * @return
     */

    public static String  getMacAddress() {
        Enumeration<NetworkInterface> networkInterfaces = null;
        StringBuilder lastest = new StringBuilder();
        Set<String> existingMacAddresses = new HashSet<>();

        try {
            networkInterfaces = NetworkInterface.getNetworkInterfaces();
        } catch (SocketException e) {
            throw new RuntimeException(e);
        }

        while (networkInterfaces.hasMoreElements()) {
            NetworkInterface networkInterface = networkInterfaces.nextElement();

            // 选择物理网卡，排除虚拟网卡和回环网卡
            try {
                if (!networkInterface.isVirtual() && !networkInterface.isLoopback()) {
                    byte[] macAddress = networkInterface.getHardwareAddress();

                    if (macAddress != null) {
                        StringBuilder sb = new StringBuilder();

                        for (byte b : macAddress) {
                            sb.append(String.format("%02x:", b));
                        }

                        if (sb.length() > 0) {
                            sb.deleteCharAt(sb.length() - 1);
                        }


                        String macAddressString = sb.toString();

                        // Check if macAddressString is already in existingMacAddresses
                        if (!existingMacAddresses.contains(macAddressString)) {
                            // Add to existingMacAddresses for future checks
                            existingMacAddresses.add(macAddressString);
                            if (lastest.length() > 0) {
                                lastest.append(";");
                                lastest.append(sb);
                            } else {


                                lastest.append(sb);
                            }
                        }
                    }
                }
            } catch (SocketException e) {
                throw new RuntimeException(e);
            }

        }

        log.info("物理网卡地址: {}", lastest);
        return lastest.toString();
    }

    /**
     * 获取mac地址
     *
     * @return mac 列表
     */
    public static List<String> getMacList() {
        ArrayList<String> list = new ArrayList<>();
        StringBuilder sb = new StringBuilder();
        try {
            Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces();
            while (en.hasMoreElements()) {
                NetworkInterface iface = en.nextElement();
                List<InterfaceAddress> addrs = iface.getInterfaceAddresses();
                for (InterfaceAddress addr : addrs) {
                    InetAddress ip = addr.getAddress();
                    if (ip.isLinkLocalAddress()) {//本地的不要
                        continue;
                    }
                    NetworkInterface network = NetworkInterface.getByInetAddress(ip);
                    if (network == null) {
                        continue;
                    }
                    byte[] mac = network.getHardwareAddress();
                    if (mac == null) {
                        continue;
                    }

                    sb.delete(0, sb.length());
                    for (int i = 0; i < mac.length; i++) {
                        sb.append(String.format("%02X%s", mac[i], (i < mac.length - 1) ? "-" : ""));
                    }
                    if (!list.contains(sb.toString())) {
                        list.add(sb.toString());
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return list;
    }

    /**
     * 获取cpu序列号
     *
     * @return 序列号
     */
    public static String getCPUSerialNumber() {
        String sysName = System.getProperty("os.name");
        if (sysName.contains("Windows")) {//win
            String str = runCmd("wmic cpu get ProcessorId", 2);
            return str;
        } else if (sysName.contains("Linux")) {
            String str = runCmd("dmidecode |grep -A16 \"Processor Information$\"", "ID");
            if (str != null) {
                return str.substring(str.indexOf(":")).trim();
            }
        } else if (sysName.contains("Mac")) {
            String str = runCmd("system_profiler SPHardwareDataType", "Serial Number");
            if (str != null) {
                return str.substring(str.indexOf(":") + 1).trim();
            }
        }
        return "";
    }

    /**
     * 获取硬盘序列号
     *
     * @return 硬盘序列号
     */
    public static String getHardDiskSerialNumber() {
        String sysName = System.getProperty("os.name");
        if (sysName.contains("Windows")) {//win
            String str = runCmd("wmic path win32_physicalmedia get serialnumber", 2);
            if (str != null) {
                String trimmed = str.replaceAll("\\s+", "");
                int startIndex = trimmed.lastIndexOf("ProcessorId") + "ProcessorId".length();
                return trimmed.substring(startIndex);
            }
        } else if (sysName.contains("Linux")) {
            String str = runCmd("dmidecode |grep -A16 \"System Information$\"", "Serial Number");
            if (str != null) {
                return str.substring(str.indexOf(":")).trim();
            }
        } else if (sysName.contains("Mac")) {
            String str = runCmd("system_profiler SPStorageDataType", "Volume UUID");
            if (str != null) {
                return str.substring(str.indexOf(":") + 1).trim();
            }
        }
        return "";
    }

    /**
     * 生成机器码
     *
     * @return 机器码
     */
    public static char[] makeMarchinCode() {
        char[] c1 = EncryptUtils.md5(getMacList().toString().toCharArray());
        char[] c2 = EncryptUtils.md5(getCPUSerialNumber().toCharArray());
        char[] c3 = EncryptUtils.md5(getHardDiskSerialNumber().toCharArray());
        char[] chars = StrUtils.merger(c2, c3);
        for (int i = 0; i < chars.length; i++) {
            chars[i] = Character.toUpperCase(chars[i]);
        }
        return chars;
    }


    public static String getMachineSlash4() {
        String macAddress = getMacAddress();
        log.info("macAddress: {}", macAddress);
        String cpuSerialNumber = getCPUSerialNumber();
        log.info("cpuSerialNumber: {}", cpuSerialNumber);
        String hardDiskSerialNumber = getHardDiskSerialNumber();
        log.info("hardDiskSerialNumber: {}", hardDiskSerialNumber);
        String s = EncryptUtils.md5Slash((macAddress + cpuSerialNumber + hardDiskSerialNumber).toCharArray());
        log.info("s: {}", s);
        return s;
    }

    public static void main(String[] args) {

        //5687c3d5-cb167c08-1a0e09f7-c52d710d  --test for crab's Mac pro laptop
        System.out.println("Divided MD5: " + getMachineSlash4());
    }
}
