// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RegisterThingInput {
    /// <p>The provisioning template. See <a href="https://docs.aws.amazon.com/iot/latest/developerguide/provision-w-cert.html">Provisioning Devices That Have Device Certificates</a> for more information.</p>
    pub template_body: ::std::option::Option<::std::string::String>,
    /// <p>The parameters for provisioning a thing. See <a href="https://docs.aws.amazon.com/iot/latest/developerguide/provision-template.html">Provisioning Templates</a> for more information.</p>
    pub parameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl RegisterThingInput {
    /// <p>The provisioning template. See <a href="https://docs.aws.amazon.com/iot/latest/developerguide/provision-w-cert.html">Provisioning Devices That Have Device Certificates</a> for more information.</p>
    pub fn template_body(&self) -> ::std::option::Option<&str> {
        self.template_body.as_deref()
    }
    /// <p>The parameters for provisioning a thing. See <a href="https://docs.aws.amazon.com/iot/latest/developerguide/provision-template.html">Provisioning Templates</a> for more information.</p>
    pub fn parameters(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.parameters.as_ref()
    }
}
impl RegisterThingInput {
    /// Creates a new builder-style object to manufacture [`RegisterThingInput`](crate::operation::register_thing::RegisterThingInput).
    pub fn builder() -> crate::operation::register_thing::builders::RegisterThingInputBuilder {
        crate::operation::register_thing::builders::RegisterThingInputBuilder::default()
    }
}

/// A builder for [`RegisterThingInput`](crate::operation::register_thing::RegisterThingInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RegisterThingInputBuilder {
    pub(crate) template_body: ::std::option::Option<::std::string::String>,
    pub(crate) parameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl RegisterThingInputBuilder {
    /// <p>The provisioning template. See <a href="https://docs.aws.amazon.com/iot/latest/developerguide/provision-w-cert.html">Provisioning Devices That Have Device Certificates</a> for more information.</p>
    /// This field is required.
    pub fn template_body(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.template_body = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The provisioning template. See <a href="https://docs.aws.amazon.com/iot/latest/developerguide/provision-w-cert.html">Provisioning Devices That Have Device Certificates</a> for more information.</p>
    pub fn set_template_body(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.template_body = input;
        self
    }
    /// <p>The provisioning template. See <a href="https://docs.aws.amazon.com/iot/latest/developerguide/provision-w-cert.html">Provisioning Devices That Have Device Certificates</a> for more information.</p>
    pub fn get_template_body(&self) -> &::std::option::Option<::std::string::String> {
        &self.template_body
    }
    /// Adds a key-value pair to `parameters`.
    ///
    /// To override the contents of this collection use [`set_parameters`](Self::set_parameters).
    ///
    /// <p>The parameters for provisioning a thing. See <a href="https://docs.aws.amazon.com/iot/latest/developerguide/provision-template.html">Provisioning Templates</a> for more information.</p>
    pub fn parameters(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.parameters.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.parameters = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The parameters for provisioning a thing. See <a href="https://docs.aws.amazon.com/iot/latest/developerguide/provision-template.html">Provisioning Templates</a> for more information.</p>
    pub fn set_parameters(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.parameters = input;
        self
    }
    /// <p>The parameters for provisioning a thing. See <a href="https://docs.aws.amazon.com/iot/latest/developerguide/provision-template.html">Provisioning Templates</a> for more information.</p>
    pub fn get_parameters(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.parameters
    }
    /// Consumes the builder and constructs a [`RegisterThingInput`](crate::operation::register_thing::RegisterThingInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::register_thing::RegisterThingInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::register_thing::RegisterThingInput {
            template_body: self.template_body,
            parameters: self.parameters,
        })
    }
}
