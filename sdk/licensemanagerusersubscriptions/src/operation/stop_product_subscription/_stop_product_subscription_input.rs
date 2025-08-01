// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StopProductSubscriptionInput {
    /// <p>The user name from the identity provider for the user.</p>
    pub username: ::std::option::Option<::std::string::String>,
    /// <p>An object that specifies details for the identity provider.</p>
    pub identity_provider: ::std::option::Option<crate::types::IdentityProvider>,
    /// <p>The name of the user-based subscription product.</p>
    /// <p>Valid values: <code>VISUAL_STUDIO_ENTERPRISE</code> | <code>VISUAL_STUDIO_PROFESSIONAL</code> | <code>OFFICE_PROFESSIONAL_PLUS</code> | <code>REMOTE_DESKTOP_SERVICES</code></p>
    pub product: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the product user.</p>
    pub product_user_arn: ::std::option::Option<::std::string::String>,
    /// <p>The domain name of the Active Directory that contains the user for whom to stop the product subscription.</p>
    pub domain: ::std::option::Option<::std::string::String>,
}
impl StopProductSubscriptionInput {
    /// <p>The user name from the identity provider for the user.</p>
    pub fn username(&self) -> ::std::option::Option<&str> {
        self.username.as_deref()
    }
    /// <p>An object that specifies details for the identity provider.</p>
    pub fn identity_provider(&self) -> ::std::option::Option<&crate::types::IdentityProvider> {
        self.identity_provider.as_ref()
    }
    /// <p>The name of the user-based subscription product.</p>
    /// <p>Valid values: <code>VISUAL_STUDIO_ENTERPRISE</code> | <code>VISUAL_STUDIO_PROFESSIONAL</code> | <code>OFFICE_PROFESSIONAL_PLUS</code> | <code>REMOTE_DESKTOP_SERVICES</code></p>
    pub fn product(&self) -> ::std::option::Option<&str> {
        self.product.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the product user.</p>
    pub fn product_user_arn(&self) -> ::std::option::Option<&str> {
        self.product_user_arn.as_deref()
    }
    /// <p>The domain name of the Active Directory that contains the user for whom to stop the product subscription.</p>
    pub fn domain(&self) -> ::std::option::Option<&str> {
        self.domain.as_deref()
    }
}
impl StopProductSubscriptionInput {
    /// Creates a new builder-style object to manufacture [`StopProductSubscriptionInput`](crate::operation::stop_product_subscription::StopProductSubscriptionInput).
    pub fn builder() -> crate::operation::stop_product_subscription::builders::StopProductSubscriptionInputBuilder {
        crate::operation::stop_product_subscription::builders::StopProductSubscriptionInputBuilder::default()
    }
}

/// A builder for [`StopProductSubscriptionInput`](crate::operation::stop_product_subscription::StopProductSubscriptionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StopProductSubscriptionInputBuilder {
    pub(crate) username: ::std::option::Option<::std::string::String>,
    pub(crate) identity_provider: ::std::option::Option<crate::types::IdentityProvider>,
    pub(crate) product: ::std::option::Option<::std::string::String>,
    pub(crate) product_user_arn: ::std::option::Option<::std::string::String>,
    pub(crate) domain: ::std::option::Option<::std::string::String>,
}
impl StopProductSubscriptionInputBuilder {
    /// <p>The user name from the identity provider for the user.</p>
    pub fn username(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.username = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The user name from the identity provider for the user.</p>
    pub fn set_username(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.username = input;
        self
    }
    /// <p>The user name from the identity provider for the user.</p>
    pub fn get_username(&self) -> &::std::option::Option<::std::string::String> {
        &self.username
    }
    /// <p>An object that specifies details for the identity provider.</p>
    pub fn identity_provider(mut self, input: crate::types::IdentityProvider) -> Self {
        self.identity_provider = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object that specifies details for the identity provider.</p>
    pub fn set_identity_provider(mut self, input: ::std::option::Option<crate::types::IdentityProvider>) -> Self {
        self.identity_provider = input;
        self
    }
    /// <p>An object that specifies details for the identity provider.</p>
    pub fn get_identity_provider(&self) -> &::std::option::Option<crate::types::IdentityProvider> {
        &self.identity_provider
    }
    /// <p>The name of the user-based subscription product.</p>
    /// <p>Valid values: <code>VISUAL_STUDIO_ENTERPRISE</code> | <code>VISUAL_STUDIO_PROFESSIONAL</code> | <code>OFFICE_PROFESSIONAL_PLUS</code> | <code>REMOTE_DESKTOP_SERVICES</code></p>
    pub fn product(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.product = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the user-based subscription product.</p>
    /// <p>Valid values: <code>VISUAL_STUDIO_ENTERPRISE</code> | <code>VISUAL_STUDIO_PROFESSIONAL</code> | <code>OFFICE_PROFESSIONAL_PLUS</code> | <code>REMOTE_DESKTOP_SERVICES</code></p>
    pub fn set_product(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.product = input;
        self
    }
    /// <p>The name of the user-based subscription product.</p>
    /// <p>Valid values: <code>VISUAL_STUDIO_ENTERPRISE</code> | <code>VISUAL_STUDIO_PROFESSIONAL</code> | <code>OFFICE_PROFESSIONAL_PLUS</code> | <code>REMOTE_DESKTOP_SERVICES</code></p>
    pub fn get_product(&self) -> &::std::option::Option<::std::string::String> {
        &self.product
    }
    /// <p>The Amazon Resource Name (ARN) of the product user.</p>
    pub fn product_user_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.product_user_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the product user.</p>
    pub fn set_product_user_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.product_user_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the product user.</p>
    pub fn get_product_user_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.product_user_arn
    }
    /// <p>The domain name of the Active Directory that contains the user for whom to stop the product subscription.</p>
    pub fn domain(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The domain name of the Active Directory that contains the user for whom to stop the product subscription.</p>
    pub fn set_domain(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain = input;
        self
    }
    /// <p>The domain name of the Active Directory that contains the user for whom to stop the product subscription.</p>
    pub fn get_domain(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain
    }
    /// Consumes the builder and constructs a [`StopProductSubscriptionInput`](crate::operation::stop_product_subscription::StopProductSubscriptionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::stop_product_subscription::StopProductSubscriptionInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::stop_product_subscription::StopProductSubscriptionInput {
            username: self.username,
            identity_provider: self.identity_provider,
            product: self.product,
            product_user_arn: self.product_user_arn,
            domain: self.domain,
        })
    }
}
