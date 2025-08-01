// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateAnycastIpListOutput {
    /// <p>A response structure that includes the version identifier (ETag) and the created <code>AnycastIpList</code> structure.</p>
    pub anycast_ip_list: ::std::option::Option<crate::types::AnycastIpList>,
    /// <p>The version identifier for the current version of the Anycast static IP list.</p>
    pub e_tag: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateAnycastIpListOutput {
    /// <p>A response structure that includes the version identifier (ETag) and the created <code>AnycastIpList</code> structure.</p>
    pub fn anycast_ip_list(&self) -> ::std::option::Option<&crate::types::AnycastIpList> {
        self.anycast_ip_list.as_ref()
    }
    /// <p>The version identifier for the current version of the Anycast static IP list.</p>
    pub fn e_tag(&self) -> ::std::option::Option<&str> {
        self.e_tag.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateAnycastIpListOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateAnycastIpListOutput {
    /// Creates a new builder-style object to manufacture [`CreateAnycastIpListOutput`](crate::operation::create_anycast_ip_list::CreateAnycastIpListOutput).
    pub fn builder() -> crate::operation::create_anycast_ip_list::builders::CreateAnycastIpListOutputBuilder {
        crate::operation::create_anycast_ip_list::builders::CreateAnycastIpListOutputBuilder::default()
    }
}

/// A builder for [`CreateAnycastIpListOutput`](crate::operation::create_anycast_ip_list::CreateAnycastIpListOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateAnycastIpListOutputBuilder {
    pub(crate) anycast_ip_list: ::std::option::Option<crate::types::AnycastIpList>,
    pub(crate) e_tag: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateAnycastIpListOutputBuilder {
    /// <p>A response structure that includes the version identifier (ETag) and the created <code>AnycastIpList</code> structure.</p>
    pub fn anycast_ip_list(mut self, input: crate::types::AnycastIpList) -> Self {
        self.anycast_ip_list = ::std::option::Option::Some(input);
        self
    }
    /// <p>A response structure that includes the version identifier (ETag) and the created <code>AnycastIpList</code> structure.</p>
    pub fn set_anycast_ip_list(mut self, input: ::std::option::Option<crate::types::AnycastIpList>) -> Self {
        self.anycast_ip_list = input;
        self
    }
    /// <p>A response structure that includes the version identifier (ETag) and the created <code>AnycastIpList</code> structure.</p>
    pub fn get_anycast_ip_list(&self) -> &::std::option::Option<crate::types::AnycastIpList> {
        &self.anycast_ip_list
    }
    /// <p>The version identifier for the current version of the Anycast static IP list.</p>
    pub fn e_tag(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.e_tag = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version identifier for the current version of the Anycast static IP list.</p>
    pub fn set_e_tag(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.e_tag = input;
        self
    }
    /// <p>The version identifier for the current version of the Anycast static IP list.</p>
    pub fn get_e_tag(&self) -> &::std::option::Option<::std::string::String> {
        &self.e_tag
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateAnycastIpListOutput`](crate::operation::create_anycast_ip_list::CreateAnycastIpListOutput).
    pub fn build(self) -> crate::operation::create_anycast_ip_list::CreateAnycastIpListOutput {
        crate::operation::create_anycast_ip_list::CreateAnycastIpListOutput {
            anycast_ip_list: self.anycast_ip_list,
            e_tag: self.e_tag,
            _request_id: self._request_id,
        }
    }
}
