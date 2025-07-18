// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The configuration of an insight visual.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InsightConfiguration {
    /// <p>The computations configurations of the insight visual</p>
    pub computations: ::std::option::Option<::std::vec::Vec<crate::types::Computation>>,
    /// <p>The custom narrative of the insight visual.</p>
    pub custom_narrative: ::std::option::Option<crate::types::CustomNarrativeOptions>,
    /// <p>The general visual interactions setup for a visual.</p>
    pub interactions: ::std::option::Option<crate::types::VisualInteractionOptions>,
}
impl InsightConfiguration {
    /// <p>The computations configurations of the insight visual</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.computations.is_none()`.
    pub fn computations(&self) -> &[crate::types::Computation] {
        self.computations.as_deref().unwrap_or_default()
    }
    /// <p>The custom narrative of the insight visual.</p>
    pub fn custom_narrative(&self) -> ::std::option::Option<&crate::types::CustomNarrativeOptions> {
        self.custom_narrative.as_ref()
    }
    /// <p>The general visual interactions setup for a visual.</p>
    pub fn interactions(&self) -> ::std::option::Option<&crate::types::VisualInteractionOptions> {
        self.interactions.as_ref()
    }
}
impl InsightConfiguration {
    /// Creates a new builder-style object to manufacture [`InsightConfiguration`](crate::types::InsightConfiguration).
    pub fn builder() -> crate::types::builders::InsightConfigurationBuilder {
        crate::types::builders::InsightConfigurationBuilder::default()
    }
}

/// A builder for [`InsightConfiguration`](crate::types::InsightConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InsightConfigurationBuilder {
    pub(crate) computations: ::std::option::Option<::std::vec::Vec<crate::types::Computation>>,
    pub(crate) custom_narrative: ::std::option::Option<crate::types::CustomNarrativeOptions>,
    pub(crate) interactions: ::std::option::Option<crate::types::VisualInteractionOptions>,
}
impl InsightConfigurationBuilder {
    /// Appends an item to `computations`.
    ///
    /// To override the contents of this collection use [`set_computations`](Self::set_computations).
    ///
    /// <p>The computations configurations of the insight visual</p>
    pub fn computations(mut self, input: crate::types::Computation) -> Self {
        let mut v = self.computations.unwrap_or_default();
        v.push(input);
        self.computations = ::std::option::Option::Some(v);
        self
    }
    /// <p>The computations configurations of the insight visual</p>
    pub fn set_computations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Computation>>) -> Self {
        self.computations = input;
        self
    }
    /// <p>The computations configurations of the insight visual</p>
    pub fn get_computations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Computation>> {
        &self.computations
    }
    /// <p>The custom narrative of the insight visual.</p>
    pub fn custom_narrative(mut self, input: crate::types::CustomNarrativeOptions) -> Self {
        self.custom_narrative = ::std::option::Option::Some(input);
        self
    }
    /// <p>The custom narrative of the insight visual.</p>
    pub fn set_custom_narrative(mut self, input: ::std::option::Option<crate::types::CustomNarrativeOptions>) -> Self {
        self.custom_narrative = input;
        self
    }
    /// <p>The custom narrative of the insight visual.</p>
    pub fn get_custom_narrative(&self) -> &::std::option::Option<crate::types::CustomNarrativeOptions> {
        &self.custom_narrative
    }
    /// <p>The general visual interactions setup for a visual.</p>
    pub fn interactions(mut self, input: crate::types::VisualInteractionOptions) -> Self {
        self.interactions = ::std::option::Option::Some(input);
        self
    }
    /// <p>The general visual interactions setup for a visual.</p>
    pub fn set_interactions(mut self, input: ::std::option::Option<crate::types::VisualInteractionOptions>) -> Self {
        self.interactions = input;
        self
    }
    /// <p>The general visual interactions setup for a visual.</p>
    pub fn get_interactions(&self) -> &::std::option::Option<crate::types::VisualInteractionOptions> {
        &self.interactions
    }
    /// Consumes the builder and constructs a [`InsightConfiguration`](crate::types::InsightConfiguration).
    pub fn build(self) -> crate::types::InsightConfiguration {
        crate::types::InsightConfiguration {
            computations: self.computations,
            custom_narrative: self.custom_narrative,
            interactions: self.interactions,
        }
    }
}
