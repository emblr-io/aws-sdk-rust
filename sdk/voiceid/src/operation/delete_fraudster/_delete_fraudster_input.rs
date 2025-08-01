// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct DeleteFraudsterInput {
    /// <p>The identifier of the domain that contains the fraudster.</p>
    pub domain_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the fraudster you want to delete.</p>
    pub fraudster_id: ::std::option::Option<::std::string::String>,
}
impl DeleteFraudsterInput {
    /// <p>The identifier of the domain that contains the fraudster.</p>
    pub fn domain_id(&self) -> ::std::option::Option<&str> {
        self.domain_id.as_deref()
    }
    /// <p>The identifier of the fraudster you want to delete.</p>
    pub fn fraudster_id(&self) -> ::std::option::Option<&str> {
        self.fraudster_id.as_deref()
    }
}
impl ::std::fmt::Debug for DeleteFraudsterInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("DeleteFraudsterInput");
        formatter.field("domain_id", &self.domain_id);
        formatter.field("fraudster_id", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl DeleteFraudsterInput {
    /// Creates a new builder-style object to manufacture [`DeleteFraudsterInput`](crate::operation::delete_fraudster::DeleteFraudsterInput).
    pub fn builder() -> crate::operation::delete_fraudster::builders::DeleteFraudsterInputBuilder {
        crate::operation::delete_fraudster::builders::DeleteFraudsterInputBuilder::default()
    }
}

/// A builder for [`DeleteFraudsterInput`](crate::operation::delete_fraudster::DeleteFraudsterInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct DeleteFraudsterInputBuilder {
    pub(crate) domain_id: ::std::option::Option<::std::string::String>,
    pub(crate) fraudster_id: ::std::option::Option<::std::string::String>,
}
impl DeleteFraudsterInputBuilder {
    /// <p>The identifier of the domain that contains the fraudster.</p>
    /// This field is required.
    pub fn domain_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the domain that contains the fraudster.</p>
    pub fn set_domain_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_id = input;
        self
    }
    /// <p>The identifier of the domain that contains the fraudster.</p>
    pub fn get_domain_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_id
    }
    /// <p>The identifier of the fraudster you want to delete.</p>
    /// This field is required.
    pub fn fraudster_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.fraudster_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the fraudster you want to delete.</p>
    pub fn set_fraudster_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.fraudster_id = input;
        self
    }
    /// <p>The identifier of the fraudster you want to delete.</p>
    pub fn get_fraudster_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.fraudster_id
    }
    /// Consumes the builder and constructs a [`DeleteFraudsterInput`](crate::operation::delete_fraudster::DeleteFraudsterInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_fraudster::DeleteFraudsterInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_fraudster::DeleteFraudsterInput {
            domain_id: self.domain_id,
            fraudster_id: self.fraudster_id,
        })
    }
}
impl ::std::fmt::Debug for DeleteFraudsterInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("DeleteFraudsterInputBuilder");
        formatter.field("domain_id", &self.domain_id);
        formatter.field("fraudster_id", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
