// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateDistributionBundleInput {
    /// <p>The name of the distribution for which to update the bundle.</p>
    /// <p>Use the <code>GetDistributions</code> action to get a list of distribution names that you can specify.</p>
    pub distribution_name: ::std::option::Option<::std::string::String>,
    /// <p>The bundle ID of the new bundle to apply to your distribution.</p>
    /// <p>Use the <code>GetDistributionBundles</code> action to get a list of distribution bundle IDs that you can specify.</p>
    pub bundle_id: ::std::option::Option<::std::string::String>,
}
impl UpdateDistributionBundleInput {
    /// <p>The name of the distribution for which to update the bundle.</p>
    /// <p>Use the <code>GetDistributions</code> action to get a list of distribution names that you can specify.</p>
    pub fn distribution_name(&self) -> ::std::option::Option<&str> {
        self.distribution_name.as_deref()
    }
    /// <p>The bundle ID of the new bundle to apply to your distribution.</p>
    /// <p>Use the <code>GetDistributionBundles</code> action to get a list of distribution bundle IDs that you can specify.</p>
    pub fn bundle_id(&self) -> ::std::option::Option<&str> {
        self.bundle_id.as_deref()
    }
}
impl UpdateDistributionBundleInput {
    /// Creates a new builder-style object to manufacture [`UpdateDistributionBundleInput`](crate::operation::update_distribution_bundle::UpdateDistributionBundleInput).
    pub fn builder() -> crate::operation::update_distribution_bundle::builders::UpdateDistributionBundleInputBuilder {
        crate::operation::update_distribution_bundle::builders::UpdateDistributionBundleInputBuilder::default()
    }
}

/// A builder for [`UpdateDistributionBundleInput`](crate::operation::update_distribution_bundle::UpdateDistributionBundleInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateDistributionBundleInputBuilder {
    pub(crate) distribution_name: ::std::option::Option<::std::string::String>,
    pub(crate) bundle_id: ::std::option::Option<::std::string::String>,
}
impl UpdateDistributionBundleInputBuilder {
    /// <p>The name of the distribution for which to update the bundle.</p>
    /// <p>Use the <code>GetDistributions</code> action to get a list of distribution names that you can specify.</p>
    pub fn distribution_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.distribution_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the distribution for which to update the bundle.</p>
    /// <p>Use the <code>GetDistributions</code> action to get a list of distribution names that you can specify.</p>
    pub fn set_distribution_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.distribution_name = input;
        self
    }
    /// <p>The name of the distribution for which to update the bundle.</p>
    /// <p>Use the <code>GetDistributions</code> action to get a list of distribution names that you can specify.</p>
    pub fn get_distribution_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.distribution_name
    }
    /// <p>The bundle ID of the new bundle to apply to your distribution.</p>
    /// <p>Use the <code>GetDistributionBundles</code> action to get a list of distribution bundle IDs that you can specify.</p>
    pub fn bundle_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bundle_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The bundle ID of the new bundle to apply to your distribution.</p>
    /// <p>Use the <code>GetDistributionBundles</code> action to get a list of distribution bundle IDs that you can specify.</p>
    pub fn set_bundle_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bundle_id = input;
        self
    }
    /// <p>The bundle ID of the new bundle to apply to your distribution.</p>
    /// <p>Use the <code>GetDistributionBundles</code> action to get a list of distribution bundle IDs that you can specify.</p>
    pub fn get_bundle_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.bundle_id
    }
    /// Consumes the builder and constructs a [`UpdateDistributionBundleInput`](crate::operation::update_distribution_bundle::UpdateDistributionBundleInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_distribution_bundle::UpdateDistributionBundleInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::update_distribution_bundle::UpdateDistributionBundleInput {
            distribution_name: self.distribution_name,
            bundle_id: self.bundle_id,
        })
    }
}
