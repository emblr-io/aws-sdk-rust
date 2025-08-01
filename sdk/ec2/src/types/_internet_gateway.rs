// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes an internet gateway.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InternetGateway {
    /// <p>Any VPCs attached to the internet gateway.</p>
    pub attachments: ::std::option::Option<::std::vec::Vec<crate::types::InternetGatewayAttachment>>,
    /// <p>The ID of the internet gateway.</p>
    pub internet_gateway_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the Amazon Web Services account that owns the internet gateway.</p>
    pub owner_id: ::std::option::Option<::std::string::String>,
    /// <p>Any tags assigned to the internet gateway.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl InternetGateway {
    /// <p>Any VPCs attached to the internet gateway.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.attachments.is_none()`.
    pub fn attachments(&self) -> &[crate::types::InternetGatewayAttachment] {
        self.attachments.as_deref().unwrap_or_default()
    }
    /// <p>The ID of the internet gateway.</p>
    pub fn internet_gateway_id(&self) -> ::std::option::Option<&str> {
        self.internet_gateway_id.as_deref()
    }
    /// <p>The ID of the Amazon Web Services account that owns the internet gateway.</p>
    pub fn owner_id(&self) -> ::std::option::Option<&str> {
        self.owner_id.as_deref()
    }
    /// <p>Any tags assigned to the internet gateway.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl InternetGateway {
    /// Creates a new builder-style object to manufacture [`InternetGateway`](crate::types::InternetGateway).
    pub fn builder() -> crate::types::builders::InternetGatewayBuilder {
        crate::types::builders::InternetGatewayBuilder::default()
    }
}

/// A builder for [`InternetGateway`](crate::types::InternetGateway).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InternetGatewayBuilder {
    pub(crate) attachments: ::std::option::Option<::std::vec::Vec<crate::types::InternetGatewayAttachment>>,
    pub(crate) internet_gateway_id: ::std::option::Option<::std::string::String>,
    pub(crate) owner_id: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl InternetGatewayBuilder {
    /// Appends an item to `attachments`.
    ///
    /// To override the contents of this collection use [`set_attachments`](Self::set_attachments).
    ///
    /// <p>Any VPCs attached to the internet gateway.</p>
    pub fn attachments(mut self, input: crate::types::InternetGatewayAttachment) -> Self {
        let mut v = self.attachments.unwrap_or_default();
        v.push(input);
        self.attachments = ::std::option::Option::Some(v);
        self
    }
    /// <p>Any VPCs attached to the internet gateway.</p>
    pub fn set_attachments(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::InternetGatewayAttachment>>) -> Self {
        self.attachments = input;
        self
    }
    /// <p>Any VPCs attached to the internet gateway.</p>
    pub fn get_attachments(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::InternetGatewayAttachment>> {
        &self.attachments
    }
    /// <p>The ID of the internet gateway.</p>
    pub fn internet_gateway_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.internet_gateway_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the internet gateway.</p>
    pub fn set_internet_gateway_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.internet_gateway_id = input;
        self
    }
    /// <p>The ID of the internet gateway.</p>
    pub fn get_internet_gateway_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.internet_gateway_id
    }
    /// <p>The ID of the Amazon Web Services account that owns the internet gateway.</p>
    pub fn owner_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.owner_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Amazon Web Services account that owns the internet gateway.</p>
    pub fn set_owner_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.owner_id = input;
        self
    }
    /// <p>The ID of the Amazon Web Services account that owns the internet gateway.</p>
    pub fn get_owner_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.owner_id
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Any tags assigned to the internet gateway.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>Any tags assigned to the internet gateway.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Any tags assigned to the internet gateway.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`InternetGateway`](crate::types::InternetGateway).
    pub fn build(self) -> crate::types::InternetGateway {
        crate::types::InternetGateway {
            attachments: self.attachments,
            internet_gateway_id: self.internet_gateway_id,
            owner_id: self.owner_id,
            tags: self.tags,
        }
    }
}
