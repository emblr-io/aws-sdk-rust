// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details related activities associated with a potential security event. Lists all distinct categories of evidence that are connected to the resource or the finding group.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RelatedFindingDetail {
    /// <p>The Amazon Resource Name (ARN) of the related finding.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The type of finding.</p>
    pub r#type: ::std::option::Option<::std::string::String>,
    /// <p>The IP address of the finding.</p>
    pub ip_address: ::std::option::Option<::std::string::String>,
}
impl RelatedFindingDetail {
    /// <p>The Amazon Resource Name (ARN) of the related finding.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The type of finding.</p>
    pub fn r#type(&self) -> ::std::option::Option<&str> {
        self.r#type.as_deref()
    }
    /// <p>The IP address of the finding.</p>
    pub fn ip_address(&self) -> ::std::option::Option<&str> {
        self.ip_address.as_deref()
    }
}
impl RelatedFindingDetail {
    /// Creates a new builder-style object to manufacture [`RelatedFindingDetail`](crate::types::RelatedFindingDetail).
    pub fn builder() -> crate::types::builders::RelatedFindingDetailBuilder {
        crate::types::builders::RelatedFindingDetailBuilder::default()
    }
}

/// A builder for [`RelatedFindingDetail`](crate::types::RelatedFindingDetail).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RelatedFindingDetailBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<::std::string::String>,
    pub(crate) ip_address: ::std::option::Option<::std::string::String>,
}
impl RelatedFindingDetailBuilder {
    /// <p>The Amazon Resource Name (ARN) of the related finding.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the related finding.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the related finding.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The type of finding.</p>
    pub fn r#type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.r#type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The type of finding.</p>
    pub fn set_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of finding.</p>
    pub fn get_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.r#type
    }
    /// <p>The IP address of the finding.</p>
    pub fn ip_address(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ip_address = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The IP address of the finding.</p>
    pub fn set_ip_address(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ip_address = input;
        self
    }
    /// <p>The IP address of the finding.</p>
    pub fn get_ip_address(&self) -> &::std::option::Option<::std::string::String> {
        &self.ip_address
    }
    /// Consumes the builder and constructs a [`RelatedFindingDetail`](crate::types::RelatedFindingDetail).
    pub fn build(self) -> crate::types::RelatedFindingDetail {
        crate::types::RelatedFindingDetail {
            arn: self.arn,
            r#type: self.r#type,
            ip_address: self.ip_address,
        }
    }
}
