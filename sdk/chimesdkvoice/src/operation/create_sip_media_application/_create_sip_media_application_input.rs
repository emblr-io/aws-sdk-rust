// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateSipMediaApplicationInput {
    /// <p>The AWS Region assigned to the SIP media application.</p>
    pub aws_region: ::std::option::Option<::std::string::String>,
    /// <p>The SIP media application's name.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>List of endpoints (Lambda ARNs) specified for the SIP media application.</p>
    pub endpoints: ::std::option::Option<::std::vec::Vec<crate::types::SipMediaApplicationEndpoint>>,
    /// <p>The tags assigned to the SIP media application.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateSipMediaApplicationInput {
    /// <p>The AWS Region assigned to the SIP media application.</p>
    pub fn aws_region(&self) -> ::std::option::Option<&str> {
        self.aws_region.as_deref()
    }
    /// <p>The SIP media application's name.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>List of endpoints (Lambda ARNs) specified for the SIP media application.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.endpoints.is_none()`.
    pub fn endpoints(&self) -> &[crate::types::SipMediaApplicationEndpoint] {
        self.endpoints.as_deref().unwrap_or_default()
    }
    /// <p>The tags assigned to the SIP media application.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl CreateSipMediaApplicationInput {
    /// Creates a new builder-style object to manufacture [`CreateSipMediaApplicationInput`](crate::operation::create_sip_media_application::CreateSipMediaApplicationInput).
    pub fn builder() -> crate::operation::create_sip_media_application::builders::CreateSipMediaApplicationInputBuilder {
        crate::operation::create_sip_media_application::builders::CreateSipMediaApplicationInputBuilder::default()
    }
}

/// A builder for [`CreateSipMediaApplicationInput`](crate::operation::create_sip_media_application::CreateSipMediaApplicationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateSipMediaApplicationInputBuilder {
    pub(crate) aws_region: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) endpoints: ::std::option::Option<::std::vec::Vec<crate::types::SipMediaApplicationEndpoint>>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateSipMediaApplicationInputBuilder {
    /// <p>The AWS Region assigned to the SIP media application.</p>
    /// This field is required.
    pub fn aws_region(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.aws_region = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The AWS Region assigned to the SIP media application.</p>
    pub fn set_aws_region(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.aws_region = input;
        self
    }
    /// <p>The AWS Region assigned to the SIP media application.</p>
    pub fn get_aws_region(&self) -> &::std::option::Option<::std::string::String> {
        &self.aws_region
    }
    /// <p>The SIP media application's name.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The SIP media application's name.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The SIP media application's name.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Appends an item to `endpoints`.
    ///
    /// To override the contents of this collection use [`set_endpoints`](Self::set_endpoints).
    ///
    /// <p>List of endpoints (Lambda ARNs) specified for the SIP media application.</p>
    pub fn endpoints(mut self, input: crate::types::SipMediaApplicationEndpoint) -> Self {
        let mut v = self.endpoints.unwrap_or_default();
        v.push(input);
        self.endpoints = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of endpoints (Lambda ARNs) specified for the SIP media application.</p>
    pub fn set_endpoints(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::SipMediaApplicationEndpoint>>) -> Self {
        self.endpoints = input;
        self
    }
    /// <p>List of endpoints (Lambda ARNs) specified for the SIP media application.</p>
    pub fn get_endpoints(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SipMediaApplicationEndpoint>> {
        &self.endpoints
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags assigned to the SIP media application.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>The tags assigned to the SIP media application.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags assigned to the SIP media application.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateSipMediaApplicationInput`](crate::operation::create_sip_media_application::CreateSipMediaApplicationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_sip_media_application::CreateSipMediaApplicationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_sip_media_application::CreateSipMediaApplicationInput {
            aws_region: self.aws_region,
            name: self.name,
            endpoints: self.endpoints,
            tags: self.tags,
        })
    }
}
