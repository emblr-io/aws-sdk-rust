// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateDeletionProtectionInput {
    /// <p>The Amazon Resource Name (ARN) of the replication set to update.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>Specifies if deletion protection is turned on or off in your account.</p>
    pub deletion_protected: ::std::option::Option<bool>,
    /// <p>A token that ensures that the operation is called only once with the specified details.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
}
impl UpdateDeletionProtectionInput {
    /// <p>The Amazon Resource Name (ARN) of the replication set to update.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>Specifies if deletion protection is turned on or off in your account.</p>
    pub fn deletion_protected(&self) -> ::std::option::Option<bool> {
        self.deletion_protected
    }
    /// <p>A token that ensures that the operation is called only once with the specified details.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
}
impl UpdateDeletionProtectionInput {
    /// Creates a new builder-style object to manufacture [`UpdateDeletionProtectionInput`](crate::operation::update_deletion_protection::UpdateDeletionProtectionInput).
    pub fn builder() -> crate::operation::update_deletion_protection::builders::UpdateDeletionProtectionInputBuilder {
        crate::operation::update_deletion_protection::builders::UpdateDeletionProtectionInputBuilder::default()
    }
}

/// A builder for [`UpdateDeletionProtectionInput`](crate::operation::update_deletion_protection::UpdateDeletionProtectionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateDeletionProtectionInputBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) deletion_protected: ::std::option::Option<bool>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
}
impl UpdateDeletionProtectionInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the replication set to update.</p>
    /// This field is required.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the replication set to update.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the replication set to update.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>Specifies if deletion protection is turned on or off in your account.</p>
    /// This field is required.
    pub fn deletion_protected(mut self, input: bool) -> Self {
        self.deletion_protected = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies if deletion protection is turned on or off in your account.</p>
    pub fn set_deletion_protected(mut self, input: ::std::option::Option<bool>) -> Self {
        self.deletion_protected = input;
        self
    }
    /// <p>Specifies if deletion protection is turned on or off in your account.</p>
    pub fn get_deletion_protected(&self) -> &::std::option::Option<bool> {
        &self.deletion_protected
    }
    /// <p>A token that ensures that the operation is called only once with the specified details.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token that ensures that the operation is called only once with the specified details.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>A token that ensures that the operation is called only once with the specified details.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// Consumes the builder and constructs a [`UpdateDeletionProtectionInput`](crate::operation::update_deletion_protection::UpdateDeletionProtectionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_deletion_protection::UpdateDeletionProtectionInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::update_deletion_protection::UpdateDeletionProtectionInput {
            arn: self.arn,
            deletion_protected: self.deletion_protected,
            client_token: self.client_token,
        })
    }
}
