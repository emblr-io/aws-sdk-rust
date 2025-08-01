// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetPartnershipInput {
    /// <p>Specifies the unique, system-generated identifier for a partnership.</p>
    pub partnership_id: ::std::option::Option<::std::string::String>,
}
impl GetPartnershipInput {
    /// <p>Specifies the unique, system-generated identifier for a partnership.</p>
    pub fn partnership_id(&self) -> ::std::option::Option<&str> {
        self.partnership_id.as_deref()
    }
}
impl GetPartnershipInput {
    /// Creates a new builder-style object to manufacture [`GetPartnershipInput`](crate::operation::get_partnership::GetPartnershipInput).
    pub fn builder() -> crate::operation::get_partnership::builders::GetPartnershipInputBuilder {
        crate::operation::get_partnership::builders::GetPartnershipInputBuilder::default()
    }
}

/// A builder for [`GetPartnershipInput`](crate::operation::get_partnership::GetPartnershipInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetPartnershipInputBuilder {
    pub(crate) partnership_id: ::std::option::Option<::std::string::String>,
}
impl GetPartnershipInputBuilder {
    /// <p>Specifies the unique, system-generated identifier for a partnership.</p>
    /// This field is required.
    pub fn partnership_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.partnership_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the unique, system-generated identifier for a partnership.</p>
    pub fn set_partnership_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.partnership_id = input;
        self
    }
    /// <p>Specifies the unique, system-generated identifier for a partnership.</p>
    pub fn get_partnership_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.partnership_id
    }
    /// Consumes the builder and constructs a [`GetPartnershipInput`](crate::operation::get_partnership::GetPartnershipInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_partnership::GetPartnershipInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_partnership::GetPartnershipInput {
            partnership_id: self.partnership_id,
        })
    }
}
