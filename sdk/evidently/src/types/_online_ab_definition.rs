// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A structure that contains the configuration of which variation to use as the "control" version. The "control" version is used for comparison with other variations. This structure also specifies how much experiment traffic is allocated to each variation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct OnlineAbDefinition {
    /// <p>The name of the variation that is the default variation that the other variations are compared to.</p>
    pub control_treatment_name: ::std::option::Option<::std::string::String>,
    /// <p>A set of key-value pairs. The keys are variation names, and the values are the portion of experiment traffic to be assigned to that variation. The traffic portion is specified in thousandths of a percent, so 20,000 for a variation would allocate 20% of the experiment traffic to that variation.</p>
    pub treatment_weights: ::std::option::Option<::std::collections::HashMap<::std::string::String, i64>>,
}
impl OnlineAbDefinition {
    /// <p>The name of the variation that is the default variation that the other variations are compared to.</p>
    pub fn control_treatment_name(&self) -> ::std::option::Option<&str> {
        self.control_treatment_name.as_deref()
    }
    /// <p>A set of key-value pairs. The keys are variation names, and the values are the portion of experiment traffic to be assigned to that variation. The traffic portion is specified in thousandths of a percent, so 20,000 for a variation would allocate 20% of the experiment traffic to that variation.</p>
    pub fn treatment_weights(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, i64>> {
        self.treatment_weights.as_ref()
    }
}
impl OnlineAbDefinition {
    /// Creates a new builder-style object to manufacture [`OnlineAbDefinition`](crate::types::OnlineAbDefinition).
    pub fn builder() -> crate::types::builders::OnlineAbDefinitionBuilder {
        crate::types::builders::OnlineAbDefinitionBuilder::default()
    }
}

/// A builder for [`OnlineAbDefinition`](crate::types::OnlineAbDefinition).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct OnlineAbDefinitionBuilder {
    pub(crate) control_treatment_name: ::std::option::Option<::std::string::String>,
    pub(crate) treatment_weights: ::std::option::Option<::std::collections::HashMap<::std::string::String, i64>>,
}
impl OnlineAbDefinitionBuilder {
    /// <p>The name of the variation that is the default variation that the other variations are compared to.</p>
    pub fn control_treatment_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.control_treatment_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the variation that is the default variation that the other variations are compared to.</p>
    pub fn set_control_treatment_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.control_treatment_name = input;
        self
    }
    /// <p>The name of the variation that is the default variation that the other variations are compared to.</p>
    pub fn get_control_treatment_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.control_treatment_name
    }
    /// Adds a key-value pair to `treatment_weights`.
    ///
    /// To override the contents of this collection use [`set_treatment_weights`](Self::set_treatment_weights).
    ///
    /// <p>A set of key-value pairs. The keys are variation names, and the values are the portion of experiment traffic to be assigned to that variation. The traffic portion is specified in thousandths of a percent, so 20,000 for a variation would allocate 20% of the experiment traffic to that variation.</p>
    pub fn treatment_weights(mut self, k: impl ::std::convert::Into<::std::string::String>, v: i64) -> Self {
        let mut hash_map = self.treatment_weights.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.treatment_weights = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A set of key-value pairs. The keys are variation names, and the values are the portion of experiment traffic to be assigned to that variation. The traffic portion is specified in thousandths of a percent, so 20,000 for a variation would allocate 20% of the experiment traffic to that variation.</p>
    pub fn set_treatment_weights(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, i64>>) -> Self {
        self.treatment_weights = input;
        self
    }
    /// <p>A set of key-value pairs. The keys are variation names, and the values are the portion of experiment traffic to be assigned to that variation. The traffic portion is specified in thousandths of a percent, so 20,000 for a variation would allocate 20% of the experiment traffic to that variation.</p>
    pub fn get_treatment_weights(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, i64>> {
        &self.treatment_weights
    }
    /// Consumes the builder and constructs a [`OnlineAbDefinition`](crate::types::OnlineAbDefinition).
    pub fn build(self) -> crate::types::OnlineAbDefinition {
        crate::types::OnlineAbDefinition {
            control_treatment_name: self.control_treatment_name,
            treatment_weights: self.treatment_weights,
        }
    }
}
