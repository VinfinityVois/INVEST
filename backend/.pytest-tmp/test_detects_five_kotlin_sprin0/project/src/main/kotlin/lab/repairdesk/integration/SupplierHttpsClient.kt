import javax.net.ssl.HostnameVerifier
class SupplierHttpsClient {
    fun connect() {
        connection.hostnameVerifier = HostnameVerifier { _, _ -> true }
    }
}
