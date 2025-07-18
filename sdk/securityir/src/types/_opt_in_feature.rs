// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct OptInFeature {
    /// <p></p>
    pub feature_name: crate::types::OptInFeatureName,
    /// <p></p>
    pub is_enabled: bool,
}
impl OptInFeature {
    /// <p></p>
    pub fn feature_name(&self) -> &crate::types::OptInFeatureName {
        &self.feature_name
    }
    /// <p></p>
    pub fn is_enabled(&self) -> bool {
        self.is_enabled
    }
}
impl OptInFeature {
    /// Creates a new builder-style object to manufacture [`OptInFeature`](crate::types::OptInFeature).
    pub fn builder() -> crate::types::builders::OptInFeatureBuilder {
        crate::types::builders::OptInFeatureBuilder::default()
    }
}

/// A builder for [`OptInFeature`](crate::types::OptInFeature).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct OptInFeatureBuilder {
    pub(crate) feature_name: ::std::option::Option<crate::types::OptInFeatureName>,
    pub(crate) is_enabled: ::std::option::Option<bool>,
}
impl OptInFeatureBuilder {
    /// <p></p>
    /// This field is required.
    pub fn feature_name(mut self, input: crate::types::OptInFeatureName) -> Self {
        self.feature_name = ::std::option::Option::Some(input);
        self
    }
    /// <p></p>
    pub fn set_feature_name(mut self, input: ::std::option::Option<crate::types::OptInFeatureName>) -> Self {
        self.feature_name = input;
        self
    }
    /// <p></p>
    pub fn get_feature_name(&self) -> &::std::option::Option<crate::types::OptInFeatureName> {
        &self.feature_name
    }
    /// <p></p>
    /// This field is required.
    pub fn is_enabled(mut self, input: bool) -> Self {
        self.is_enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p></p>
    pub fn set_is_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.is_enabled = input;
        self
    }
    /// <p></p>
    pub fn get_is_enabled(&self) -> &::std::option::Option<bool> {
        &self.is_enabled
    }
    /// Consumes the builder and constructs a [`OptInFeature`](crate::types::OptInFeature).
    /// This method will fail if any of the following fields are not set:
    /// - [`feature_name`](crate::types::builders::OptInFeatureBuilder::feature_name)
    /// - [`is_enabled`](crate::types::builders::OptInFeatureBuilder::is_enabled)
    pub fn build(self) -> ::std::result::Result<crate::types::OptInFeature, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::OptInFeature {
            feature_name: self.feature_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "feature_name",
                    "feature_name was not specified but it is required when building OptInFeature",
                )
            })?,
            is_enabled: self.is_enabled.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "is_enabled",
                    "is_enabled was not specified but it is required when building OptInFeature",
                )
            })?,
        })
    }
}
