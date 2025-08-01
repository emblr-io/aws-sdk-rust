// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the drift check model quality baselines that can be used when the model monitor is set using the model package.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DriftCheckModelQuality {
    /// <p>The drift check model quality statistics.</p>
    pub statistics: ::std::option::Option<crate::types::MetricsSource>,
    /// <p>The drift check model quality constraints.</p>
    pub constraints: ::std::option::Option<crate::types::MetricsSource>,
}
impl DriftCheckModelQuality {
    /// <p>The drift check model quality statistics.</p>
    pub fn statistics(&self) -> ::std::option::Option<&crate::types::MetricsSource> {
        self.statistics.as_ref()
    }
    /// <p>The drift check model quality constraints.</p>
    pub fn constraints(&self) -> ::std::option::Option<&crate::types::MetricsSource> {
        self.constraints.as_ref()
    }
}
impl DriftCheckModelQuality {
    /// Creates a new builder-style object to manufacture [`DriftCheckModelQuality`](crate::types::DriftCheckModelQuality).
    pub fn builder() -> crate::types::builders::DriftCheckModelQualityBuilder {
        crate::types::builders::DriftCheckModelQualityBuilder::default()
    }
}

/// A builder for [`DriftCheckModelQuality`](crate::types::DriftCheckModelQuality).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DriftCheckModelQualityBuilder {
    pub(crate) statistics: ::std::option::Option<crate::types::MetricsSource>,
    pub(crate) constraints: ::std::option::Option<crate::types::MetricsSource>,
}
impl DriftCheckModelQualityBuilder {
    /// <p>The drift check model quality statistics.</p>
    pub fn statistics(mut self, input: crate::types::MetricsSource) -> Self {
        self.statistics = ::std::option::Option::Some(input);
        self
    }
    /// <p>The drift check model quality statistics.</p>
    pub fn set_statistics(mut self, input: ::std::option::Option<crate::types::MetricsSource>) -> Self {
        self.statistics = input;
        self
    }
    /// <p>The drift check model quality statistics.</p>
    pub fn get_statistics(&self) -> &::std::option::Option<crate::types::MetricsSource> {
        &self.statistics
    }
    /// <p>The drift check model quality constraints.</p>
    pub fn constraints(mut self, input: crate::types::MetricsSource) -> Self {
        self.constraints = ::std::option::Option::Some(input);
        self
    }
    /// <p>The drift check model quality constraints.</p>
    pub fn set_constraints(mut self, input: ::std::option::Option<crate::types::MetricsSource>) -> Self {
        self.constraints = input;
        self
    }
    /// <p>The drift check model quality constraints.</p>
    pub fn get_constraints(&self) -> &::std::option::Option<crate::types::MetricsSource> {
        &self.constraints
    }
    /// Consumes the builder and constructs a [`DriftCheckModelQuality`](crate::types::DriftCheckModelQuality).
    pub fn build(self) -> crate::types::DriftCheckModelQuality {
        crate::types::DriftCheckModelQuality {
            statistics: self.statistics,
            constraints: self.constraints,
        }
    }
}
