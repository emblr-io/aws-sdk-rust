// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A list of security controls and control parameter values that are included in a configuration policy.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SecurityControlCustomParameter {
    /// <p>The ID of the security control.</p>
    pub security_control_id: ::std::option::Option<::std::string::String>,
    /// <p>An object that specifies parameter values for a control in a configuration policy.</p>
    pub parameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::ParameterConfiguration>>,
}
impl SecurityControlCustomParameter {
    /// <p>The ID of the security control.</p>
    pub fn security_control_id(&self) -> ::std::option::Option<&str> {
        self.security_control_id.as_deref()
    }
    /// <p>An object that specifies parameter values for a control in a configuration policy.</p>
    pub fn parameters(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, crate::types::ParameterConfiguration>> {
        self.parameters.as_ref()
    }
}
impl SecurityControlCustomParameter {
    /// Creates a new builder-style object to manufacture [`SecurityControlCustomParameter`](crate::types::SecurityControlCustomParameter).
    pub fn builder() -> crate::types::builders::SecurityControlCustomParameterBuilder {
        crate::types::builders::SecurityControlCustomParameterBuilder::default()
    }
}

/// A builder for [`SecurityControlCustomParameter`](crate::types::SecurityControlCustomParameter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SecurityControlCustomParameterBuilder {
    pub(crate) security_control_id: ::std::option::Option<::std::string::String>,
    pub(crate) parameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::ParameterConfiguration>>,
}
impl SecurityControlCustomParameterBuilder {
    /// <p>The ID of the security control.</p>
    pub fn security_control_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.security_control_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the security control.</p>
    pub fn set_security_control_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.security_control_id = input;
        self
    }
    /// <p>The ID of the security control.</p>
    pub fn get_security_control_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.security_control_id
    }
    /// Adds a key-value pair to `parameters`.
    ///
    /// To override the contents of this collection use [`set_parameters`](Self::set_parameters).
    ///
    /// <p>An object that specifies parameter values for a control in a configuration policy.</p>
    pub fn parameters(mut self, k: impl ::std::convert::Into<::std::string::String>, v: crate::types::ParameterConfiguration) -> Self {
        let mut hash_map = self.parameters.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.parameters = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>An object that specifies parameter values for a control in a configuration policy.</p>
    pub fn set_parameters(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::ParameterConfiguration>>,
    ) -> Self {
        self.parameters = input;
        self
    }
    /// <p>An object that specifies parameter values for a control in a configuration policy.</p>
    pub fn get_parameters(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::ParameterConfiguration>> {
        &self.parameters
    }
    /// Consumes the builder and constructs a [`SecurityControlCustomParameter`](crate::types::SecurityControlCustomParameter).
    pub fn build(self) -> crate::types::SecurityControlCustomParameter {
        crate::types::SecurityControlCustomParameter {
            security_control_id: self.security_control_id,
            parameters: self.parameters,
        }
    }
}
