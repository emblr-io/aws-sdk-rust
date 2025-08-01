// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Filters a conformance pack by Config rule names, compliance types, Amazon Web Services resource types, and resource IDs.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ConformancePackEvaluationFilters {
    /// <p>Filters the results by Config rule names.</p>
    pub config_rule_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Filters the results by compliance.</p>
    /// <p>The allowed values are <code>COMPLIANT</code> and <code>NON_COMPLIANT</code>. <code>INSUFFICIENT_DATA</code> is not supported.</p>
    pub compliance_type: ::std::option::Option<crate::types::ConformancePackComplianceType>,
    /// <p>Filters the results by the resource type (for example, <code>"AWS::EC2::Instance"</code>).</p>
    pub resource_type: ::std::option::Option<::std::string::String>,
    /// <p>Filters the results by resource IDs.</p><note>
    /// <p>This is valid only when you provide resource type. If there is no resource type, you will see an error.</p>
    /// </note>
    pub resource_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl ConformancePackEvaluationFilters {
    /// <p>Filters the results by Config rule names.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.config_rule_names.is_none()`.
    pub fn config_rule_names(&self) -> &[::std::string::String] {
        self.config_rule_names.as_deref().unwrap_or_default()
    }
    /// <p>Filters the results by compliance.</p>
    /// <p>The allowed values are <code>COMPLIANT</code> and <code>NON_COMPLIANT</code>. <code>INSUFFICIENT_DATA</code> is not supported.</p>
    pub fn compliance_type(&self) -> ::std::option::Option<&crate::types::ConformancePackComplianceType> {
        self.compliance_type.as_ref()
    }
    /// <p>Filters the results by the resource type (for example, <code>"AWS::EC2::Instance"</code>).</p>
    pub fn resource_type(&self) -> ::std::option::Option<&str> {
        self.resource_type.as_deref()
    }
    /// <p>Filters the results by resource IDs.</p><note>
    /// <p>This is valid only when you provide resource type. If there is no resource type, you will see an error.</p>
    /// </note>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.resource_ids.is_none()`.
    pub fn resource_ids(&self) -> &[::std::string::String] {
        self.resource_ids.as_deref().unwrap_or_default()
    }
}
impl ConformancePackEvaluationFilters {
    /// Creates a new builder-style object to manufacture [`ConformancePackEvaluationFilters`](crate::types::ConformancePackEvaluationFilters).
    pub fn builder() -> crate::types::builders::ConformancePackEvaluationFiltersBuilder {
        crate::types::builders::ConformancePackEvaluationFiltersBuilder::default()
    }
}

/// A builder for [`ConformancePackEvaluationFilters`](crate::types::ConformancePackEvaluationFilters).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ConformancePackEvaluationFiltersBuilder {
    pub(crate) config_rule_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) compliance_type: ::std::option::Option<crate::types::ConformancePackComplianceType>,
    pub(crate) resource_type: ::std::option::Option<::std::string::String>,
    pub(crate) resource_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl ConformancePackEvaluationFiltersBuilder {
    /// Appends an item to `config_rule_names`.
    ///
    /// To override the contents of this collection use [`set_config_rule_names`](Self::set_config_rule_names).
    ///
    /// <p>Filters the results by Config rule names.</p>
    pub fn config_rule_names(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.config_rule_names.unwrap_or_default();
        v.push(input.into());
        self.config_rule_names = ::std::option::Option::Some(v);
        self
    }
    /// <p>Filters the results by Config rule names.</p>
    pub fn set_config_rule_names(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.config_rule_names = input;
        self
    }
    /// <p>Filters the results by Config rule names.</p>
    pub fn get_config_rule_names(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.config_rule_names
    }
    /// <p>Filters the results by compliance.</p>
    /// <p>The allowed values are <code>COMPLIANT</code> and <code>NON_COMPLIANT</code>. <code>INSUFFICIENT_DATA</code> is not supported.</p>
    pub fn compliance_type(mut self, input: crate::types::ConformancePackComplianceType) -> Self {
        self.compliance_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Filters the results by compliance.</p>
    /// <p>The allowed values are <code>COMPLIANT</code> and <code>NON_COMPLIANT</code>. <code>INSUFFICIENT_DATA</code> is not supported.</p>
    pub fn set_compliance_type(mut self, input: ::std::option::Option<crate::types::ConformancePackComplianceType>) -> Self {
        self.compliance_type = input;
        self
    }
    /// <p>Filters the results by compliance.</p>
    /// <p>The allowed values are <code>COMPLIANT</code> and <code>NON_COMPLIANT</code>. <code>INSUFFICIENT_DATA</code> is not supported.</p>
    pub fn get_compliance_type(&self) -> &::std::option::Option<crate::types::ConformancePackComplianceType> {
        &self.compliance_type
    }
    /// <p>Filters the results by the resource type (for example, <code>"AWS::EC2::Instance"</code>).</p>
    pub fn resource_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Filters the results by the resource type (for example, <code>"AWS::EC2::Instance"</code>).</p>
    pub fn set_resource_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_type = input;
        self
    }
    /// <p>Filters the results by the resource type (for example, <code>"AWS::EC2::Instance"</code>).</p>
    pub fn get_resource_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_type
    }
    /// Appends an item to `resource_ids`.
    ///
    /// To override the contents of this collection use [`set_resource_ids`](Self::set_resource_ids).
    ///
    /// <p>Filters the results by resource IDs.</p><note>
    /// <p>This is valid only when you provide resource type. If there is no resource type, you will see an error.</p>
    /// </note>
    pub fn resource_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.resource_ids.unwrap_or_default();
        v.push(input.into());
        self.resource_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>Filters the results by resource IDs.</p><note>
    /// <p>This is valid only when you provide resource type. If there is no resource type, you will see an error.</p>
    /// </note>
    pub fn set_resource_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.resource_ids = input;
        self
    }
    /// <p>Filters the results by resource IDs.</p><note>
    /// <p>This is valid only when you provide resource type. If there is no resource type, you will see an error.</p>
    /// </note>
    pub fn get_resource_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.resource_ids
    }
    /// Consumes the builder and constructs a [`ConformancePackEvaluationFilters`](crate::types::ConformancePackEvaluationFilters).
    pub fn build(self) -> crate::types::ConformancePackEvaluationFilters {
        crate::types::ConformancePackEvaluationFilters {
            config_rule_names: self.config_rule_names,
            compliance_type: self.compliance_type,
            resource_type: self.resource_type,
            resource_ids: self.resource_ids,
        }
    }
}
