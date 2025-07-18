// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides the configuration information required for Amazon Kendra Web Crawler.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct WebCrawlerConfiguration {
    /// <p>Specifies the seed or starting point URLs of the websites or the sitemap URLs of the websites you want to crawl.</p>
    /// <p>You can include website subdomains. You can list up to 100 seed URLs and up to three sitemap URLs.</p>
    /// <p>You can only crawl websites that use the secure communication protocol, Hypertext Transfer Protocol Secure (HTTPS). If you receive an error when crawling a website, it could be that the website is blocked from crawling.</p>
    /// <p><i>When selecting websites to index, you must adhere to the <a href="https://aws.amazon.com/aup/">Amazon Acceptable Use Policy</a> and all other Amazon terms. Remember that you must only use Amazon Kendra Web Crawler to index your own web pages, or web pages that you have authorization to index.</i></p>
    pub urls: ::std::option::Option<crate::types::Urls>,
    /// <p>The 'depth' or number of levels from the seed level to crawl. For example, the seed URL page is depth 1 and any hyperlinks on this page that are also crawled are depth 2.</p>
    pub crawl_depth: ::std::option::Option<i32>,
    /// <p>The maximum number of URLs on a web page to include when crawling a website. This number is per web page.</p>
    /// <p>As a website’s web pages are crawled, any URLs the web pages link to are also crawled. URLs on a web page are crawled in order of appearance.</p>
    /// <p>The default maximum links per page is 100.</p>
    pub max_links_per_page: ::std::option::Option<i32>,
    /// <p>The maximum size (in MB) of a web page or attachment to crawl.</p>
    /// <p>Files larger than this size (in MB) are skipped/not crawled.</p>
    /// <p>The default maximum size of a web page or attachment is set to 50 MB.</p>
    pub max_content_size_per_page_in_mega_bytes: ::std::option::Option<f32>,
    /// <p>The maximum number of URLs crawled per website host per minute.</p>
    /// <p>A minimum of one URL is required.</p>
    /// <p>The default maximum number of URLs crawled per website host per minute is 300.</p>
    pub max_urls_per_minute_crawl_rate: ::std::option::Option<i32>,
    /// <p>A list of regular expression patterns to include certain URLs to crawl. URLs that match the patterns are included in the index. URLs that don't match the patterns are excluded from the index. If a URL matches both an inclusion and exclusion pattern, the exclusion pattern takes precedence and the URL file isn't included in the index.</p>
    pub url_inclusion_patterns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>A list of regular expression patterns to exclude certain URLs to crawl. URLs that match the patterns are excluded from the index. URLs that don't match the patterns are included in the index. If a URL matches both an inclusion and exclusion pattern, the exclusion pattern takes precedence and the URL file isn't included in the index.</p>
    pub url_exclusion_patterns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Configuration information required to connect to your internal websites via a web proxy.</p>
    /// <p>You must provide the website host name and port number. For example, the host name of https://a.example.com/page1.html is "a.example.com" and the port is 443, the standard port for HTTPS.</p>
    /// <p>Web proxy credentials are optional and you can use them to connect to a web proxy server that requires basic authentication. To store web proxy credentials, you use a secret in <a href="https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html">Secrets Manager</a>.</p>
    pub proxy_configuration: ::std::option::Option<crate::types::ProxyConfiguration>,
    /// <p>Configuration information required to connect to websites using authentication.</p>
    /// <p>You can connect to websites using basic authentication of user name and password. You use a secret in <a href="https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html">Secrets Manager</a> to store your authentication credentials.</p>
    /// <p>You must provide the website host name and port number. For example, the host name of https://a.example.com/page1.html is "a.example.com" and the port is 443, the standard port for HTTPS.</p>
    pub authentication_configuration: ::std::option::Option<crate::types::AuthenticationConfiguration>,
}
impl WebCrawlerConfiguration {
    /// <p>Specifies the seed or starting point URLs of the websites or the sitemap URLs of the websites you want to crawl.</p>
    /// <p>You can include website subdomains. You can list up to 100 seed URLs and up to three sitemap URLs.</p>
    /// <p>You can only crawl websites that use the secure communication protocol, Hypertext Transfer Protocol Secure (HTTPS). If you receive an error when crawling a website, it could be that the website is blocked from crawling.</p>
    /// <p><i>When selecting websites to index, you must adhere to the <a href="https://aws.amazon.com/aup/">Amazon Acceptable Use Policy</a> and all other Amazon terms. Remember that you must only use Amazon Kendra Web Crawler to index your own web pages, or web pages that you have authorization to index.</i></p>
    pub fn urls(&self) -> ::std::option::Option<&crate::types::Urls> {
        self.urls.as_ref()
    }
    /// <p>The 'depth' or number of levels from the seed level to crawl. For example, the seed URL page is depth 1 and any hyperlinks on this page that are also crawled are depth 2.</p>
    pub fn crawl_depth(&self) -> ::std::option::Option<i32> {
        self.crawl_depth
    }
    /// <p>The maximum number of URLs on a web page to include when crawling a website. This number is per web page.</p>
    /// <p>As a website’s web pages are crawled, any URLs the web pages link to are also crawled. URLs on a web page are crawled in order of appearance.</p>
    /// <p>The default maximum links per page is 100.</p>
    pub fn max_links_per_page(&self) -> ::std::option::Option<i32> {
        self.max_links_per_page
    }
    /// <p>The maximum size (in MB) of a web page or attachment to crawl.</p>
    /// <p>Files larger than this size (in MB) are skipped/not crawled.</p>
    /// <p>The default maximum size of a web page or attachment is set to 50 MB.</p>
    pub fn max_content_size_per_page_in_mega_bytes(&self) -> ::std::option::Option<f32> {
        self.max_content_size_per_page_in_mega_bytes
    }
    /// <p>The maximum number of URLs crawled per website host per minute.</p>
    /// <p>A minimum of one URL is required.</p>
    /// <p>The default maximum number of URLs crawled per website host per minute is 300.</p>
    pub fn max_urls_per_minute_crawl_rate(&self) -> ::std::option::Option<i32> {
        self.max_urls_per_minute_crawl_rate
    }
    /// <p>A list of regular expression patterns to include certain URLs to crawl. URLs that match the patterns are included in the index. URLs that don't match the patterns are excluded from the index. If a URL matches both an inclusion and exclusion pattern, the exclusion pattern takes precedence and the URL file isn't included in the index.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.url_inclusion_patterns.is_none()`.
    pub fn url_inclusion_patterns(&self) -> &[::std::string::String] {
        self.url_inclusion_patterns.as_deref().unwrap_or_default()
    }
    /// <p>A list of regular expression patterns to exclude certain URLs to crawl. URLs that match the patterns are excluded from the index. URLs that don't match the patterns are included in the index. If a URL matches both an inclusion and exclusion pattern, the exclusion pattern takes precedence and the URL file isn't included in the index.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.url_exclusion_patterns.is_none()`.
    pub fn url_exclusion_patterns(&self) -> &[::std::string::String] {
        self.url_exclusion_patterns.as_deref().unwrap_or_default()
    }
    /// <p>Configuration information required to connect to your internal websites via a web proxy.</p>
    /// <p>You must provide the website host name and port number. For example, the host name of https://a.example.com/page1.html is "a.example.com" and the port is 443, the standard port for HTTPS.</p>
    /// <p>Web proxy credentials are optional and you can use them to connect to a web proxy server that requires basic authentication. To store web proxy credentials, you use a secret in <a href="https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html">Secrets Manager</a>.</p>
    pub fn proxy_configuration(&self) -> ::std::option::Option<&crate::types::ProxyConfiguration> {
        self.proxy_configuration.as_ref()
    }
    /// <p>Configuration information required to connect to websites using authentication.</p>
    /// <p>You can connect to websites using basic authentication of user name and password. You use a secret in <a href="https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html">Secrets Manager</a> to store your authentication credentials.</p>
    /// <p>You must provide the website host name and port number. For example, the host name of https://a.example.com/page1.html is "a.example.com" and the port is 443, the standard port for HTTPS.</p>
    pub fn authentication_configuration(&self) -> ::std::option::Option<&crate::types::AuthenticationConfiguration> {
        self.authentication_configuration.as_ref()
    }
}
impl WebCrawlerConfiguration {
    /// Creates a new builder-style object to manufacture [`WebCrawlerConfiguration`](crate::types::WebCrawlerConfiguration).
    pub fn builder() -> crate::types::builders::WebCrawlerConfigurationBuilder {
        crate::types::builders::WebCrawlerConfigurationBuilder::default()
    }
}

/// A builder for [`WebCrawlerConfiguration`](crate::types::WebCrawlerConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct WebCrawlerConfigurationBuilder {
    pub(crate) urls: ::std::option::Option<crate::types::Urls>,
    pub(crate) crawl_depth: ::std::option::Option<i32>,
    pub(crate) max_links_per_page: ::std::option::Option<i32>,
    pub(crate) max_content_size_per_page_in_mega_bytes: ::std::option::Option<f32>,
    pub(crate) max_urls_per_minute_crawl_rate: ::std::option::Option<i32>,
    pub(crate) url_inclusion_patterns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) url_exclusion_patterns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) proxy_configuration: ::std::option::Option<crate::types::ProxyConfiguration>,
    pub(crate) authentication_configuration: ::std::option::Option<crate::types::AuthenticationConfiguration>,
}
impl WebCrawlerConfigurationBuilder {
    /// <p>Specifies the seed or starting point URLs of the websites or the sitemap URLs of the websites you want to crawl.</p>
    /// <p>You can include website subdomains. You can list up to 100 seed URLs and up to three sitemap URLs.</p>
    /// <p>You can only crawl websites that use the secure communication protocol, Hypertext Transfer Protocol Secure (HTTPS). If you receive an error when crawling a website, it could be that the website is blocked from crawling.</p>
    /// <p><i>When selecting websites to index, you must adhere to the <a href="https://aws.amazon.com/aup/">Amazon Acceptable Use Policy</a> and all other Amazon terms. Remember that you must only use Amazon Kendra Web Crawler to index your own web pages, or web pages that you have authorization to index.</i></p>
    /// This field is required.
    pub fn urls(mut self, input: crate::types::Urls) -> Self {
        self.urls = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the seed or starting point URLs of the websites or the sitemap URLs of the websites you want to crawl.</p>
    /// <p>You can include website subdomains. You can list up to 100 seed URLs and up to three sitemap URLs.</p>
    /// <p>You can only crawl websites that use the secure communication protocol, Hypertext Transfer Protocol Secure (HTTPS). If you receive an error when crawling a website, it could be that the website is blocked from crawling.</p>
    /// <p><i>When selecting websites to index, you must adhere to the <a href="https://aws.amazon.com/aup/">Amazon Acceptable Use Policy</a> and all other Amazon terms. Remember that you must only use Amazon Kendra Web Crawler to index your own web pages, or web pages that you have authorization to index.</i></p>
    pub fn set_urls(mut self, input: ::std::option::Option<crate::types::Urls>) -> Self {
        self.urls = input;
        self
    }
    /// <p>Specifies the seed or starting point URLs of the websites or the sitemap URLs of the websites you want to crawl.</p>
    /// <p>You can include website subdomains. You can list up to 100 seed URLs and up to three sitemap URLs.</p>
    /// <p>You can only crawl websites that use the secure communication protocol, Hypertext Transfer Protocol Secure (HTTPS). If you receive an error when crawling a website, it could be that the website is blocked from crawling.</p>
    /// <p><i>When selecting websites to index, you must adhere to the <a href="https://aws.amazon.com/aup/">Amazon Acceptable Use Policy</a> and all other Amazon terms. Remember that you must only use Amazon Kendra Web Crawler to index your own web pages, or web pages that you have authorization to index.</i></p>
    pub fn get_urls(&self) -> &::std::option::Option<crate::types::Urls> {
        &self.urls
    }
    /// <p>The 'depth' or number of levels from the seed level to crawl. For example, the seed URL page is depth 1 and any hyperlinks on this page that are also crawled are depth 2.</p>
    pub fn crawl_depth(mut self, input: i32) -> Self {
        self.crawl_depth = ::std::option::Option::Some(input);
        self
    }
    /// <p>The 'depth' or number of levels from the seed level to crawl. For example, the seed URL page is depth 1 and any hyperlinks on this page that are also crawled are depth 2.</p>
    pub fn set_crawl_depth(mut self, input: ::std::option::Option<i32>) -> Self {
        self.crawl_depth = input;
        self
    }
    /// <p>The 'depth' or number of levels from the seed level to crawl. For example, the seed URL page is depth 1 and any hyperlinks on this page that are also crawled are depth 2.</p>
    pub fn get_crawl_depth(&self) -> &::std::option::Option<i32> {
        &self.crawl_depth
    }
    /// <p>The maximum number of URLs on a web page to include when crawling a website. This number is per web page.</p>
    /// <p>As a website’s web pages are crawled, any URLs the web pages link to are also crawled. URLs on a web page are crawled in order of appearance.</p>
    /// <p>The default maximum links per page is 100.</p>
    pub fn max_links_per_page(mut self, input: i32) -> Self {
        self.max_links_per_page = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of URLs on a web page to include when crawling a website. This number is per web page.</p>
    /// <p>As a website’s web pages are crawled, any URLs the web pages link to are also crawled. URLs on a web page are crawled in order of appearance.</p>
    /// <p>The default maximum links per page is 100.</p>
    pub fn set_max_links_per_page(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_links_per_page = input;
        self
    }
    /// <p>The maximum number of URLs on a web page to include when crawling a website. This number is per web page.</p>
    /// <p>As a website’s web pages are crawled, any URLs the web pages link to are also crawled. URLs on a web page are crawled in order of appearance.</p>
    /// <p>The default maximum links per page is 100.</p>
    pub fn get_max_links_per_page(&self) -> &::std::option::Option<i32> {
        &self.max_links_per_page
    }
    /// <p>The maximum size (in MB) of a web page or attachment to crawl.</p>
    /// <p>Files larger than this size (in MB) are skipped/not crawled.</p>
    /// <p>The default maximum size of a web page or attachment is set to 50 MB.</p>
    pub fn max_content_size_per_page_in_mega_bytes(mut self, input: f32) -> Self {
        self.max_content_size_per_page_in_mega_bytes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum size (in MB) of a web page or attachment to crawl.</p>
    /// <p>Files larger than this size (in MB) are skipped/not crawled.</p>
    /// <p>The default maximum size of a web page or attachment is set to 50 MB.</p>
    pub fn set_max_content_size_per_page_in_mega_bytes(mut self, input: ::std::option::Option<f32>) -> Self {
        self.max_content_size_per_page_in_mega_bytes = input;
        self
    }
    /// <p>The maximum size (in MB) of a web page or attachment to crawl.</p>
    /// <p>Files larger than this size (in MB) are skipped/not crawled.</p>
    /// <p>The default maximum size of a web page or attachment is set to 50 MB.</p>
    pub fn get_max_content_size_per_page_in_mega_bytes(&self) -> &::std::option::Option<f32> {
        &self.max_content_size_per_page_in_mega_bytes
    }
    /// <p>The maximum number of URLs crawled per website host per minute.</p>
    /// <p>A minimum of one URL is required.</p>
    /// <p>The default maximum number of URLs crawled per website host per minute is 300.</p>
    pub fn max_urls_per_minute_crawl_rate(mut self, input: i32) -> Self {
        self.max_urls_per_minute_crawl_rate = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of URLs crawled per website host per minute.</p>
    /// <p>A minimum of one URL is required.</p>
    /// <p>The default maximum number of URLs crawled per website host per minute is 300.</p>
    pub fn set_max_urls_per_minute_crawl_rate(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_urls_per_minute_crawl_rate = input;
        self
    }
    /// <p>The maximum number of URLs crawled per website host per minute.</p>
    /// <p>A minimum of one URL is required.</p>
    /// <p>The default maximum number of URLs crawled per website host per minute is 300.</p>
    pub fn get_max_urls_per_minute_crawl_rate(&self) -> &::std::option::Option<i32> {
        &self.max_urls_per_minute_crawl_rate
    }
    /// Appends an item to `url_inclusion_patterns`.
    ///
    /// To override the contents of this collection use [`set_url_inclusion_patterns`](Self::set_url_inclusion_patterns).
    ///
    /// <p>A list of regular expression patterns to include certain URLs to crawl. URLs that match the patterns are included in the index. URLs that don't match the patterns are excluded from the index. If a URL matches both an inclusion and exclusion pattern, the exclusion pattern takes precedence and the URL file isn't included in the index.</p>
    pub fn url_inclusion_patterns(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.url_inclusion_patterns.unwrap_or_default();
        v.push(input.into());
        self.url_inclusion_patterns = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of regular expression patterns to include certain URLs to crawl. URLs that match the patterns are included in the index. URLs that don't match the patterns are excluded from the index. If a URL matches both an inclusion and exclusion pattern, the exclusion pattern takes precedence and the URL file isn't included in the index.</p>
    pub fn set_url_inclusion_patterns(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.url_inclusion_patterns = input;
        self
    }
    /// <p>A list of regular expression patterns to include certain URLs to crawl. URLs that match the patterns are included in the index. URLs that don't match the patterns are excluded from the index. If a URL matches both an inclusion and exclusion pattern, the exclusion pattern takes precedence and the URL file isn't included in the index.</p>
    pub fn get_url_inclusion_patterns(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.url_inclusion_patterns
    }
    /// Appends an item to `url_exclusion_patterns`.
    ///
    /// To override the contents of this collection use [`set_url_exclusion_patterns`](Self::set_url_exclusion_patterns).
    ///
    /// <p>A list of regular expression patterns to exclude certain URLs to crawl. URLs that match the patterns are excluded from the index. URLs that don't match the patterns are included in the index. If a URL matches both an inclusion and exclusion pattern, the exclusion pattern takes precedence and the URL file isn't included in the index.</p>
    pub fn url_exclusion_patterns(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.url_exclusion_patterns.unwrap_or_default();
        v.push(input.into());
        self.url_exclusion_patterns = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of regular expression patterns to exclude certain URLs to crawl. URLs that match the patterns are excluded from the index. URLs that don't match the patterns are included in the index. If a URL matches both an inclusion and exclusion pattern, the exclusion pattern takes precedence and the URL file isn't included in the index.</p>
    pub fn set_url_exclusion_patterns(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.url_exclusion_patterns = input;
        self
    }
    /// <p>A list of regular expression patterns to exclude certain URLs to crawl. URLs that match the patterns are excluded from the index. URLs that don't match the patterns are included in the index. If a URL matches both an inclusion and exclusion pattern, the exclusion pattern takes precedence and the URL file isn't included in the index.</p>
    pub fn get_url_exclusion_patterns(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.url_exclusion_patterns
    }
    /// <p>Configuration information required to connect to your internal websites via a web proxy.</p>
    /// <p>You must provide the website host name and port number. For example, the host name of https://a.example.com/page1.html is "a.example.com" and the port is 443, the standard port for HTTPS.</p>
    /// <p>Web proxy credentials are optional and you can use them to connect to a web proxy server that requires basic authentication. To store web proxy credentials, you use a secret in <a href="https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html">Secrets Manager</a>.</p>
    pub fn proxy_configuration(mut self, input: crate::types::ProxyConfiguration) -> Self {
        self.proxy_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Configuration information required to connect to your internal websites via a web proxy.</p>
    /// <p>You must provide the website host name and port number. For example, the host name of https://a.example.com/page1.html is "a.example.com" and the port is 443, the standard port for HTTPS.</p>
    /// <p>Web proxy credentials are optional and you can use them to connect to a web proxy server that requires basic authentication. To store web proxy credentials, you use a secret in <a href="https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html">Secrets Manager</a>.</p>
    pub fn set_proxy_configuration(mut self, input: ::std::option::Option<crate::types::ProxyConfiguration>) -> Self {
        self.proxy_configuration = input;
        self
    }
    /// <p>Configuration information required to connect to your internal websites via a web proxy.</p>
    /// <p>You must provide the website host name and port number. For example, the host name of https://a.example.com/page1.html is "a.example.com" and the port is 443, the standard port for HTTPS.</p>
    /// <p>Web proxy credentials are optional and you can use them to connect to a web proxy server that requires basic authentication. To store web proxy credentials, you use a secret in <a href="https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html">Secrets Manager</a>.</p>
    pub fn get_proxy_configuration(&self) -> &::std::option::Option<crate::types::ProxyConfiguration> {
        &self.proxy_configuration
    }
    /// <p>Configuration information required to connect to websites using authentication.</p>
    /// <p>You can connect to websites using basic authentication of user name and password. You use a secret in <a href="https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html">Secrets Manager</a> to store your authentication credentials.</p>
    /// <p>You must provide the website host name and port number. For example, the host name of https://a.example.com/page1.html is "a.example.com" and the port is 443, the standard port for HTTPS.</p>
    pub fn authentication_configuration(mut self, input: crate::types::AuthenticationConfiguration) -> Self {
        self.authentication_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Configuration information required to connect to websites using authentication.</p>
    /// <p>You can connect to websites using basic authentication of user name and password. You use a secret in <a href="https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html">Secrets Manager</a> to store your authentication credentials.</p>
    /// <p>You must provide the website host name and port number. For example, the host name of https://a.example.com/page1.html is "a.example.com" and the port is 443, the standard port for HTTPS.</p>
    pub fn set_authentication_configuration(mut self, input: ::std::option::Option<crate::types::AuthenticationConfiguration>) -> Self {
        self.authentication_configuration = input;
        self
    }
    /// <p>Configuration information required to connect to websites using authentication.</p>
    /// <p>You can connect to websites using basic authentication of user name and password. You use a secret in <a href="https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html">Secrets Manager</a> to store your authentication credentials.</p>
    /// <p>You must provide the website host name and port number. For example, the host name of https://a.example.com/page1.html is "a.example.com" and the port is 443, the standard port for HTTPS.</p>
    pub fn get_authentication_configuration(&self) -> &::std::option::Option<crate::types::AuthenticationConfiguration> {
        &self.authentication_configuration
    }
    /// Consumes the builder and constructs a [`WebCrawlerConfiguration`](crate::types::WebCrawlerConfiguration).
    pub fn build(self) -> crate::types::WebCrawlerConfiguration {
        crate::types::WebCrawlerConfiguration {
            urls: self.urls,
            crawl_depth: self.crawl_depth,
            max_links_per_page: self.max_links_per_page,
            max_content_size_per_page_in_mega_bytes: self.max_content_size_per_page_in_mega_bytes,
            max_urls_per_minute_crawl_rate: self.max_urls_per_minute_crawl_rate,
            url_inclusion_patterns: self.url_inclusion_patterns,
            url_exclusion_patterns: self.url_exclusion_patterns,
            proxy_configuration: self.proxy_configuration,
            authentication_configuration: self.authentication_configuration,
        }
    }
}
