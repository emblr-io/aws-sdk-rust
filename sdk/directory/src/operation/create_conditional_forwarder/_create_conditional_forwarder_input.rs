// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Initiates the creation of a conditional forwarder for your Directory Service for Microsoft Active Directory. Conditional forwarders are required in order to set up a trust relationship with another domain.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateConditionalForwarderInput {
    /// <p>The directory ID of the Amazon Web Services directory for which you are creating the conditional forwarder.</p>
    pub directory_id: ::std::option::Option<::std::string::String>,
    /// <p>The fully qualified domain name (FQDN) of the remote domain with which you will set up a trust relationship.</p>
    pub remote_domain_name: ::std::option::Option<::std::string::String>,
    /// <p>The IP addresses of the remote DNS server associated with RemoteDomainName.</p>
    pub dns_ip_addrs: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl CreateConditionalForwarderInput {
    /// <p>The directory ID of the Amazon Web Services directory for which you are creating the conditional forwarder.</p>
    pub fn directory_id(&self) -> ::std::option::Option<&str> {
        self.directory_id.as_deref()
    }
    /// <p>The fully qualified domain name (FQDN) of the remote domain with which you will set up a trust relationship.</p>
    pub fn remote_domain_name(&self) -> ::std::option::Option<&str> {
        self.remote_domain_name.as_deref()
    }
    /// <p>The IP addresses of the remote DNS server associated with RemoteDomainName.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.dns_ip_addrs.is_none()`.
    pub fn dns_ip_addrs(&self) -> &[::std::string::String] {
        self.dns_ip_addrs.as_deref().unwrap_or_default()
    }
}
impl CreateConditionalForwarderInput {
    /// Creates a new builder-style object to manufacture [`CreateConditionalForwarderInput`](crate::operation::create_conditional_forwarder::CreateConditionalForwarderInput).
    pub fn builder() -> crate::operation::create_conditional_forwarder::builders::CreateConditionalForwarderInputBuilder {
        crate::operation::create_conditional_forwarder::builders::CreateConditionalForwarderInputBuilder::default()
    }
}

/// A builder for [`CreateConditionalForwarderInput`](crate::operation::create_conditional_forwarder::CreateConditionalForwarderInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateConditionalForwarderInputBuilder {
    pub(crate) directory_id: ::std::option::Option<::std::string::String>,
    pub(crate) remote_domain_name: ::std::option::Option<::std::string::String>,
    pub(crate) dns_ip_addrs: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl CreateConditionalForwarderInputBuilder {
    /// <p>The directory ID of the Amazon Web Services directory for which you are creating the conditional forwarder.</p>
    /// This field is required.
    pub fn directory_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.directory_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The directory ID of the Amazon Web Services directory for which you are creating the conditional forwarder.</p>
    pub fn set_directory_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.directory_id = input;
        self
    }
    /// <p>The directory ID of the Amazon Web Services directory for which you are creating the conditional forwarder.</p>
    pub fn get_directory_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.directory_id
    }
    /// <p>The fully qualified domain name (FQDN) of the remote domain with which you will set up a trust relationship.</p>
    /// This field is required.
    pub fn remote_domain_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.remote_domain_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The fully qualified domain name (FQDN) of the remote domain with which you will set up a trust relationship.</p>
    pub fn set_remote_domain_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.remote_domain_name = input;
        self
    }
    /// <p>The fully qualified domain name (FQDN) of the remote domain with which you will set up a trust relationship.</p>
    pub fn get_remote_domain_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.remote_domain_name
    }
    /// Appends an item to `dns_ip_addrs`.
    ///
    /// To override the contents of this collection use [`set_dns_ip_addrs`](Self::set_dns_ip_addrs).
    ///
    /// <p>The IP addresses of the remote DNS server associated with RemoteDomainName.</p>
    pub fn dns_ip_addrs(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.dns_ip_addrs.unwrap_or_default();
        v.push(input.into());
        self.dns_ip_addrs = ::std::option::Option::Some(v);
        self
    }
    /// <p>The IP addresses of the remote DNS server associated with RemoteDomainName.</p>
    pub fn set_dns_ip_addrs(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.dns_ip_addrs = input;
        self
    }
    /// <p>The IP addresses of the remote DNS server associated with RemoteDomainName.</p>
    pub fn get_dns_ip_addrs(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.dns_ip_addrs
    }
    /// Consumes the builder and constructs a [`CreateConditionalForwarderInput`](crate::operation::create_conditional_forwarder::CreateConditionalForwarderInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_conditional_forwarder::CreateConditionalForwarderInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_conditional_forwarder::CreateConditionalForwarderInput {
            directory_id: self.directory_id,
            remote_domain_name: self.remote_domain_name,
            dns_ip_addrs: self.dns_ip_addrs,
        })
    }
}
