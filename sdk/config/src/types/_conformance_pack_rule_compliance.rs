// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Compliance information of one or more Config rules within a conformance pack. You can filter using Config rule names and compliance types.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ConformancePackRuleCompliance {
    /// <p>Name of the Config rule.</p>
    pub config_rule_name: ::std::option::Option<::std::string::String>,
    /// <p>Compliance of the Config rule.</p>
    pub compliance_type: ::std::option::Option<crate::types::ConformancePackComplianceType>,
    /// <p>Controls for the conformance pack. A control is a process to prevent or detect problems while meeting objectives. A control can align with a specific compliance regime or map to internal controls defined by an organization.</p>
    pub controls: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl ConformancePackRuleCompliance {
    /// <p>Name of the Config rule.</p>
    pub fn config_rule_name(&self) -> ::std::option::Option<&str> {
        self.config_rule_name.as_deref()
    }
    /// <p>Compliance of the Config rule.</p>
    pub fn compliance_type(&self) -> ::std::option::Option<&crate::types::ConformancePackComplianceType> {
        self.compliance_type.as_ref()
    }
    /// <p>Controls for the conformance pack. A control is a process to prevent or detect problems while meeting objectives. A control can align with a specific compliance regime or map to internal controls defined by an organization.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.controls.is_none()`.
    pub fn controls(&self) -> &[::std::string::String] {
        self.controls.as_deref().unwrap_or_default()
    }
}
impl ConformancePackRuleCompliance {
    /// Creates a new builder-style object to manufacture [`ConformancePackRuleCompliance`](crate::types::ConformancePackRuleCompliance).
    pub fn builder() -> crate::types::builders::ConformancePackRuleComplianceBuilder {
        crate::types::builders::ConformancePackRuleComplianceBuilder::default()
    }
}

/// A builder for [`ConformancePackRuleCompliance`](crate::types::ConformancePackRuleCompliance).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ConformancePackRuleComplianceBuilder {
    pub(crate) config_rule_name: ::std::option::Option<::std::string::String>,
    pub(crate) compliance_type: ::std::option::Option<crate::types::ConformancePackComplianceType>,
    pub(crate) controls: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl ConformancePackRuleComplianceBuilder {
    /// <p>Name of the Config rule.</p>
    pub fn config_rule_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.config_rule_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Name of the Config rule.</p>
    pub fn set_config_rule_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.config_rule_name = input;
        self
    }
    /// <p>Name of the Config rule.</p>
    pub fn get_config_rule_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.config_rule_name
    }
    /// <p>Compliance of the Config rule.</p>
    pub fn compliance_type(mut self, input: crate::types::ConformancePackComplianceType) -> Self {
        self.compliance_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Compliance of the Config rule.</p>
    pub fn set_compliance_type(mut self, input: ::std::option::Option<crate::types::ConformancePackComplianceType>) -> Self {
        self.compliance_type = input;
        self
    }
    /// <p>Compliance of the Config rule.</p>
    pub fn get_compliance_type(&self) -> &::std::option::Option<crate::types::ConformancePackComplianceType> {
        &self.compliance_type
    }
    /// Appends an item to `controls`.
    ///
    /// To override the contents of this collection use [`set_controls`](Self::set_controls).
    ///
    /// <p>Controls for the conformance pack. A control is a process to prevent or detect problems while meeting objectives. A control can align with a specific compliance regime or map to internal controls defined by an organization.</p>
    pub fn controls(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.controls.unwrap_or_default();
        v.push(input.into());
        self.controls = ::std::option::Option::Some(v);
        self
    }
    /// <p>Controls for the conformance pack. A control is a process to prevent or detect problems while meeting objectives. A control can align with a specific compliance regime or map to internal controls defined by an organization.</p>
    pub fn set_controls(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.controls = input;
        self
    }
    /// <p>Controls for the conformance pack. A control is a process to prevent or detect problems while meeting objectives. A control can align with a specific compliance regime or map to internal controls defined by an organization.</p>
    pub fn get_controls(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.controls
    }
    /// Consumes the builder and constructs a [`ConformancePackRuleCompliance`](crate::types::ConformancePackRuleCompliance).
    pub fn build(self) -> crate::types::ConformancePackRuleCompliance {
        crate::types::ConformancePackRuleCompliance {
            config_rule_name: self.config_rule_name,
            compliance_type: self.compliance_type,
            controls: self.controls,
        }
    }
}
