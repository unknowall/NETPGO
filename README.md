# **NETPGO**
![GPLv3 License](https://img.shields.io/badge/License-GPL%203.0-blue.svg?logo=gnu) ![Research Use Only](https://img.shields.io/badge/Intended%20Use-Protocol%20Research%20Only-red.svg)<br>
NETPGO 是一款功能强大且灵活的科学上网工具，专为支持多种代理协议而设计。无论您是需要穿透复杂的网络环境，还是希望为任意程序提供代理支持，NETPGO 都能为您提供高效、便捷的解决方案。

## **⚠️ LEGAL NOTICE & INTENDED USE**
This project is a network protocol analysis framework designed for:  
- Academic research on communication protocols  
- Enterprise network debugging in controlled environments  
- Cybersecurity defense mechanism development  

Any other usage, particularly for bypassing network security measures without explicit authorization, violates the fundamental purpose of this tool and may constitute illegal activity in many jurisdictions.  

## **⚠️ 法律声明与预期用途**
本项目是一个网络协议分析框架，专为以下用途设计：

- 通信协议的学术研究
- 受控环境中的企业网络调试
- 网络安全防御机制的开发

任何其他用途，尤其是未经授权规避网络安全措施的行为，均违反了本工具的基本目的，并可能在许多司法管辖区构成违法行为。

## ⚠️ 双属地法律约束
本仓库受GitHub服务条款及开发者所在司法管辖区法律双重约束。您访问或使用本项目的任一行为，即视为：
1. 承诺不用于任何国家关键信息基础设施
2. 接受中国《网络安全法》第二十一条约束
3. 确认不违反美国出口管制条例（EAR）
4. 不在中国境内搭建跨网通道
5. 不接入《中国禁止出口技术目录》所列技术

## **核心功能**  

- **多协议支持**：支持多种主流代理协议，适应各种复杂网络环境的需求。
- **IPv4/IPv6/UDP 穿透**：无论是 IPv4 还是 IPv6 环境，NETPGO 都能实现无缝穿透，并支持 UDP 协议传输。
- **全程序代理**：通过驱动层实现的代理支持，无需对目标程序进行注入操作，即可让任意程序通过代理连接（即使该程序本身不支持代理）。
- **即开即用**：无需额外依赖，解压即用，简单高效。
- **零配置启动**：简单易用，无需复杂设置，快速上手。


## **支持的代理协议**  
NETPGO 支持以下主流代理协议，确保您能够自由选择最适合的方案：  

- **V2GO**
- **Clash**
- **Quick**
- **Sing-box**
- **NaiveProxy**
- **SSR-plugin**
- **Hysteria**


## **特色亮点**  
- **免安装设计**：无需安装，解压即用，占用资源少，运行效率高。
- **驱动级代理**：基于底层驱动技术，避免传统注入方式的兼容性问题，稳定性更强。
- **日志与监控**：实时查看网络连接状态和日志信息，方便排查问题。
- **高度可定制**：支持灵活修改设置，满足个性化需求。

## **注意事项**  
在使用 NETPGO 时，请注意以下几点：  

1. **代理服务需自行准备**  
   NETPGO 不提供任何形式的代理服务或节点支持。请使用合法合规的代理服务器，并确保其来源可靠。

2. **订阅地址仅供参考**  
   Release 中包含的代理订阅地址来源于网络收集，仅供测试使用，不保证长期有效。建议您根据实际需求自行添加可靠的订阅源。

3. **合法合规使用**  
   请确保您的使用行为符合当地法律法规，NETPGO 开发者不对因不当使用导致的后果负责。

4. **零数据记录**<br>
   本工具不记录任何网络流量元数据

5. **证书验证**<br>
   本工具强制开启TLS 1.3完整握手验证

## **常见问题**
Q: 为什么需要管理员权限？  
A: 驱动级网络过滤需要内核模式操作权限

Q: 如何验证流量加密？  
A: 使用Wireshark捕获本地回环流量


## **界面展示**  
以下是 NETPGO 的部分界面截图，帮助您快速了解其功能布局和操作体验：

### 启动后的主界面  
![netpgo](https://github.com/user-attachments/assets/0ad040c8-7e0d-4b94-b94d-9dfc01dd635a)

### 主界面功能区  
![netpgo-srv](https://github.com/user-attachments/assets/f10767a8-8578-482e-9717-3dfb9b74a91e)  
![netpgo-dirs](https://github.com/user-attachments/assets/396454df-101e-478c-9c8f-835bae330e19)

### 查看网络连接状态  
![netpgo-link](https://github.com/user-attachments/assets/be308bc9-fb14-471e-9d95-506f49ce32e8)

### 查看日志信息  
![netpgo-log](https://github.com/user-attachments/assets/9234d18a-f59b-4923-9a43-844499508064)

### 修改设置  
![netpgo-set](https://github.com/user-attachments/assets/ec9a8b97-b48a-4a54-b5a9-d870aed513d5)


## **为什么选择 NETPGO？**  
- **高效稳定**：基于先进的驱动技术，确保代理的高效性和稳定性。
- **易于使用**：简洁直观的界面设计，即使是新手也能快速上手。
- **广泛兼容**：支持多种主流代理协议，满足多样化的使用需求。
- **完全免费**：开源项目，无需任何费用，您可以自由下载和使用。


## **贡献与反馈**  
NETPGO 是一个开源项目，非常欢迎您的参与和支持！如果您有任何建议、发现 Bug 或希望贡献代码，请随时通过以下方式联系：  

- **GitHub Issues**：[提交问题或建议](https://github.com/unknowall/NETPGO/issues)


## **重要提示**  
本项目仅用于技术学习、研究及合法合规的网络测试。<br>
使用者必须遵守所在国家/地区的法律法规，不得用于任何非法用途。<br>
开发者不对因不当使用导致的后果承担责任。<br>

This project is intended solely for technical learning, research, and legally compliant network testing. <br>
Users must comply with the laws and regulations of their country/region and must not use it for any illegal purposes. <br>
The developer assumes no responsibility for any consequences resulting from improper use.<br>

