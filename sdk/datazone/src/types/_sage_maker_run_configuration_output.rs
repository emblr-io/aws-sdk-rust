// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The Amazon SageMaker run configuration.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SageMakerRunConfigurationOutput {
    /// <p>The Amazon SageMaker account ID.</p>
    pub account_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon SageMaker Region.</p>
    pub region: ::std::option::Option<::std::string::String>,
    /// <p>The tracking assets of the Amazon SageMaker.</p>
    pub tracking_assets: ::std::collections::HashMap<::std::string::String, ::std::vec::Vec<::std::string::String>>,
}
impl SageMakerRunConfigurationOutput {
    /// <p>The Amazon SageMaker account ID.</p>
    pub fn account_id(&self) -> ::std::option::Option<&str> {
        self.account_id.as_deref()
    }
    /// <p>The Amazon SageMaker Region.</p>
    pub fn region(&self) -> ::std::option::Option<&str> {
        self.region.as_deref()
    }
    /// <p>The tracking assets of the Amazon SageMaker.</p>
    pub fn tracking_assets(&self) -> &::std::collections::HashMap<::std::string::String, ::std::vec::Vec<::std::string::String>> {
        &self.tracking_assets
    }
}
impl SageMakerRunConfigurationOutput {
    /// Creates a new builder-style object to manufacture [`SageMakerRunConfigurationOutput`](crate::types::SageMakerRunConfigurationOutput).
    pub fn builder() -> crate::types::builders::SageMakerRunConfigurationOutputBuilder {
        crate::types::builders::SageMakerRunConfigurationOutputBuilder::default()
    }
}

/// A builder for [`SageMakerRunConfigurationOutput`](crate::types::SageMakerRunConfigurationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SageMakerRunConfigurationOutputBuilder {
    pub(crate) account_id: ::std::option::Option<::std::string::String>,
    pub(crate) region: ::std::option::Option<::std::string::String>,
    pub(crate) tracking_assets: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::vec::Vec<::std::string::String>>>,
}
impl SageMakerRunConfigurationOutputBuilder {
    /// <p>The Amazon SageMaker account ID.</p>
    pub fn account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon SageMaker account ID.</p>
    pub fn set_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account_id = input;
        self
    }
    /// <p>The Amazon SageMaker account ID.</p>
    pub fn get_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.account_id
    }
    /// <p>The Amazon SageMaker Region.</p>
    pub fn region(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.region = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon SageMaker Region.</p>
    pub fn set_region(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.region = input;
        self
    }
    /// <p>The Amazon SageMaker Region.</p>
    pub fn get_region(&self) -> &::std::option::Option<::std::string::String> {
        &self.region
    }
    /// Adds a key-value pair to `tracking_assets`.
    ///
    /// To override the contents of this collection use [`set_tracking_assets`](Self::set_tracking_assets).
    ///
    /// <p>The tracking assets of the Amazon SageMaker.</p>
    pub fn tracking_assets(mut self, k: impl ::std::convert::Into<::std::string::String>, v: ::std::vec::Vec<::std::string::String>) -> Self {
        let mut hash_map = self.tracking_assets.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.tracking_assets = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The tracking assets of the Amazon SageMaker.</p>
    pub fn set_tracking_assets(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::vec::Vec<::std::string::String>>>,
    ) -> Self {
        self.tracking_assets = input;
        self
    }
    /// <p>The tracking assets of the Amazon SageMaker.</p>
    pub fn get_tracking_assets(
        &self,
    ) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::vec::Vec<::std::string::String>>> {
        &self.tracking_assets
    }
    /// Consumes the builder and constructs a [`SageMakerRunConfigurationOutput`](crate::types::SageMakerRunConfigurationOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`tracking_assets`](crate::types::builders::SageMakerRunConfigurationOutputBuilder::tracking_assets)
    pub fn build(self) -> ::std::result::Result<crate::types::SageMakerRunConfigurationOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::SageMakerRunConfigurationOutput {
            account_id: self.account_id,
            region: self.region,
            tracking_assets: self.tracking_assets.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "tracking_assets",
                    "tracking_assets was not specified but it is required when building SageMakerRunConfigurationOutput",
                )
            })?,
        })
    }
}
