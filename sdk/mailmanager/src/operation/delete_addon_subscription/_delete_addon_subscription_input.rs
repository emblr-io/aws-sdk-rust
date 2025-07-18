// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteAddonSubscriptionInput {
    /// <p>The Add On subscription ID to delete.</p>
    pub addon_subscription_id: ::std::option::Option<::std::string::String>,
}
impl DeleteAddonSubscriptionInput {
    /// <p>The Add On subscription ID to delete.</p>
    pub fn addon_subscription_id(&self) -> ::std::option::Option<&str> {
        self.addon_subscription_id.as_deref()
    }
}
impl DeleteAddonSubscriptionInput {
    /// Creates a new builder-style object to manufacture [`DeleteAddonSubscriptionInput`](crate::operation::delete_addon_subscription::DeleteAddonSubscriptionInput).
    pub fn builder() -> crate::operation::delete_addon_subscription::builders::DeleteAddonSubscriptionInputBuilder {
        crate::operation::delete_addon_subscription::builders::DeleteAddonSubscriptionInputBuilder::default()
    }
}

/// A builder for [`DeleteAddonSubscriptionInput`](crate::operation::delete_addon_subscription::DeleteAddonSubscriptionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteAddonSubscriptionInputBuilder {
    pub(crate) addon_subscription_id: ::std::option::Option<::std::string::String>,
}
impl DeleteAddonSubscriptionInputBuilder {
    /// <p>The Add On subscription ID to delete.</p>
    /// This field is required.
    pub fn addon_subscription_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.addon_subscription_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Add On subscription ID to delete.</p>
    pub fn set_addon_subscription_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.addon_subscription_id = input;
        self
    }
    /// <p>The Add On subscription ID to delete.</p>
    pub fn get_addon_subscription_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.addon_subscription_id
    }
    /// Consumes the builder and constructs a [`DeleteAddonSubscriptionInput`](crate::operation::delete_addon_subscription::DeleteAddonSubscriptionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_addon_subscription::DeleteAddonSubscriptionInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_addon_subscription::DeleteAddonSubscriptionInput {
            addon_subscription_id: self.addon_subscription_id,
        })
    }
}
