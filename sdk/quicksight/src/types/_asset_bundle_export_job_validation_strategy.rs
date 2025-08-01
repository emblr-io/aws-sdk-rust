// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The option to relax the validation that is required to export each asset. When <code>StrictModeForAllResource</code> is set to <code>false</code>, validation is skipped for specific UI errors.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssetBundleExportJobValidationStrategy {
    /// <p>A Boolean value that indicates whether to export resources under strict or lenient mode.</p>
    pub strict_mode_for_all_resources: bool,
}
impl AssetBundleExportJobValidationStrategy {
    /// <p>A Boolean value that indicates whether to export resources under strict or lenient mode.</p>
    pub fn strict_mode_for_all_resources(&self) -> bool {
        self.strict_mode_for_all_resources
    }
}
impl AssetBundleExportJobValidationStrategy {
    /// Creates a new builder-style object to manufacture [`AssetBundleExportJobValidationStrategy`](crate::types::AssetBundleExportJobValidationStrategy).
    pub fn builder() -> crate::types::builders::AssetBundleExportJobValidationStrategyBuilder {
        crate::types::builders::AssetBundleExportJobValidationStrategyBuilder::default()
    }
}

/// A builder for [`AssetBundleExportJobValidationStrategy`](crate::types::AssetBundleExportJobValidationStrategy).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssetBundleExportJobValidationStrategyBuilder {
    pub(crate) strict_mode_for_all_resources: ::std::option::Option<bool>,
}
impl AssetBundleExportJobValidationStrategyBuilder {
    /// <p>A Boolean value that indicates whether to export resources under strict or lenient mode.</p>
    pub fn strict_mode_for_all_resources(mut self, input: bool) -> Self {
        self.strict_mode_for_all_resources = ::std::option::Option::Some(input);
        self
    }
    /// <p>A Boolean value that indicates whether to export resources under strict or lenient mode.</p>
    pub fn set_strict_mode_for_all_resources(mut self, input: ::std::option::Option<bool>) -> Self {
        self.strict_mode_for_all_resources = input;
        self
    }
    /// <p>A Boolean value that indicates whether to export resources under strict or lenient mode.</p>
    pub fn get_strict_mode_for_all_resources(&self) -> &::std::option::Option<bool> {
        &self.strict_mode_for_all_resources
    }
    /// Consumes the builder and constructs a [`AssetBundleExportJobValidationStrategy`](crate::types::AssetBundleExportJobValidationStrategy).
    pub fn build(self) -> crate::types::AssetBundleExportJobValidationStrategy {
        crate::types::AssetBundleExportJobValidationStrategy {
            strict_mode_for_all_resources: self.strict_mode_for_all_resources.unwrap_or_default(),
        }
    }
}
