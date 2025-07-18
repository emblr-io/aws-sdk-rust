// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteManagedLoginBrandingInput {
    /// <p>The ID of the managed login branding style that you want to delete.</p>
    pub managed_login_branding_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the user pool that contains the managed login branding style that you want to delete.</p>
    pub user_pool_id: ::std::option::Option<::std::string::String>,
}
impl DeleteManagedLoginBrandingInput {
    /// <p>The ID of the managed login branding style that you want to delete.</p>
    pub fn managed_login_branding_id(&self) -> ::std::option::Option<&str> {
        self.managed_login_branding_id.as_deref()
    }
    /// <p>The ID of the user pool that contains the managed login branding style that you want to delete.</p>
    pub fn user_pool_id(&self) -> ::std::option::Option<&str> {
        self.user_pool_id.as_deref()
    }
}
impl DeleteManagedLoginBrandingInput {
    /// Creates a new builder-style object to manufacture [`DeleteManagedLoginBrandingInput`](crate::operation::delete_managed_login_branding::DeleteManagedLoginBrandingInput).
    pub fn builder() -> crate::operation::delete_managed_login_branding::builders::DeleteManagedLoginBrandingInputBuilder {
        crate::operation::delete_managed_login_branding::builders::DeleteManagedLoginBrandingInputBuilder::default()
    }
}

/// A builder for [`DeleteManagedLoginBrandingInput`](crate::operation::delete_managed_login_branding::DeleteManagedLoginBrandingInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteManagedLoginBrandingInputBuilder {
    pub(crate) managed_login_branding_id: ::std::option::Option<::std::string::String>,
    pub(crate) user_pool_id: ::std::option::Option<::std::string::String>,
}
impl DeleteManagedLoginBrandingInputBuilder {
    /// <p>The ID of the managed login branding style that you want to delete.</p>
    /// This field is required.
    pub fn managed_login_branding_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.managed_login_branding_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the managed login branding style that you want to delete.</p>
    pub fn set_managed_login_branding_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.managed_login_branding_id = input;
        self
    }
    /// <p>The ID of the managed login branding style that you want to delete.</p>
    pub fn get_managed_login_branding_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.managed_login_branding_id
    }
    /// <p>The ID of the user pool that contains the managed login branding style that you want to delete.</p>
    /// This field is required.
    pub fn user_pool_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.user_pool_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the user pool that contains the managed login branding style that you want to delete.</p>
    pub fn set_user_pool_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.user_pool_id = input;
        self
    }
    /// <p>The ID of the user pool that contains the managed login branding style that you want to delete.</p>
    pub fn get_user_pool_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.user_pool_id
    }
    /// Consumes the builder and constructs a [`DeleteManagedLoginBrandingInput`](crate::operation::delete_managed_login_branding::DeleteManagedLoginBrandingInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_managed_login_branding::DeleteManagedLoginBrandingInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_managed_login_branding::DeleteManagedLoginBrandingInput {
            managed_login_branding_id: self.managed_login_branding_id,
            user_pool_id: self.user_pool_id,
        })
    }
}
