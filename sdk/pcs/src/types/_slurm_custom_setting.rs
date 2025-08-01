// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Additional settings that directly map to Slurm settings.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SlurmCustomSetting {
    /// <p>Amazon Web Services PCS supports configuration of the following Slurm parameters:</p>
    /// <ul>
    /// <li>
    /// <p>For <b>clusters</b></p>
    /// <ul>
    /// <li>
    /// <p><a href="https://slurm.schedmd.com/slurm.conf.html#OPT_Prolog_1"> <code>Prolog</code> </a></p></li>
    /// <li>
    /// <p><a href="https://slurm.schedmd.com/slurm.conf.html#OPT_Epilog_1"> <code>Epilog</code> </a></p></li>
    /// <li>
    /// <p><a href="https://slurm.schedmd.com/slurm.conf.html#OPT_SelectTypeParameters"> <code>SelectTypeParameters</code> </a></p></li>
    /// </ul></li>
    /// <li>
    /// <p>For <b>compute node groups</b></p>
    /// <ul>
    /// <li>
    /// <p><a href="https://slurm.schedmd.com/slurm.conf.html#OPT_Weight"> <code>Weight</code> </a></p></li>
    /// <li>
    /// <p><a href="https://slurm.schedmd.com/slurm.conf.html#OPT_Weight"> <code>RealMemory</code> </a></p></li>
    /// </ul></li>
    /// </ul>
    pub parameter_name: ::std::string::String,
    /// <p>The values for the configured Slurm settings.</p>
    pub parameter_value: ::std::string::String,
}
impl SlurmCustomSetting {
    /// <p>Amazon Web Services PCS supports configuration of the following Slurm parameters:</p>
    /// <ul>
    /// <li>
    /// <p>For <b>clusters</b></p>
    /// <ul>
    /// <li>
    /// <p><a href="https://slurm.schedmd.com/slurm.conf.html#OPT_Prolog_1"> <code>Prolog</code> </a></p></li>
    /// <li>
    /// <p><a href="https://slurm.schedmd.com/slurm.conf.html#OPT_Epilog_1"> <code>Epilog</code> </a></p></li>
    /// <li>
    /// <p><a href="https://slurm.schedmd.com/slurm.conf.html#OPT_SelectTypeParameters"> <code>SelectTypeParameters</code> </a></p></li>
    /// </ul></li>
    /// <li>
    /// <p>For <b>compute node groups</b></p>
    /// <ul>
    /// <li>
    /// <p><a href="https://slurm.schedmd.com/slurm.conf.html#OPT_Weight"> <code>Weight</code> </a></p></li>
    /// <li>
    /// <p><a href="https://slurm.schedmd.com/slurm.conf.html#OPT_Weight"> <code>RealMemory</code> </a></p></li>
    /// </ul></li>
    /// </ul>
    pub fn parameter_name(&self) -> &str {
        use std::ops::Deref;
        self.parameter_name.deref()
    }
    /// <p>The values for the configured Slurm settings.</p>
    pub fn parameter_value(&self) -> &str {
        use std::ops::Deref;
        self.parameter_value.deref()
    }
}
impl SlurmCustomSetting {
    /// Creates a new builder-style object to manufacture [`SlurmCustomSetting`](crate::types::SlurmCustomSetting).
    pub fn builder() -> crate::types::builders::SlurmCustomSettingBuilder {
        crate::types::builders::SlurmCustomSettingBuilder::default()
    }
}

/// A builder for [`SlurmCustomSetting`](crate::types::SlurmCustomSetting).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SlurmCustomSettingBuilder {
    pub(crate) parameter_name: ::std::option::Option<::std::string::String>,
    pub(crate) parameter_value: ::std::option::Option<::std::string::String>,
}
impl SlurmCustomSettingBuilder {
    /// <p>Amazon Web Services PCS supports configuration of the following Slurm parameters:</p>
    /// <ul>
    /// <li>
    /// <p>For <b>clusters</b></p>
    /// <ul>
    /// <li>
    /// <p><a href="https://slurm.schedmd.com/slurm.conf.html#OPT_Prolog_1"> <code>Prolog</code> </a></p></li>
    /// <li>
    /// <p><a href="https://slurm.schedmd.com/slurm.conf.html#OPT_Epilog_1"> <code>Epilog</code> </a></p></li>
    /// <li>
    /// <p><a href="https://slurm.schedmd.com/slurm.conf.html#OPT_SelectTypeParameters"> <code>SelectTypeParameters</code> </a></p></li>
    /// </ul></li>
    /// <li>
    /// <p>For <b>compute node groups</b></p>
    /// <ul>
    /// <li>
    /// <p><a href="https://slurm.schedmd.com/slurm.conf.html#OPT_Weight"> <code>Weight</code> </a></p></li>
    /// <li>
    /// <p><a href="https://slurm.schedmd.com/slurm.conf.html#OPT_Weight"> <code>RealMemory</code> </a></p></li>
    /// </ul></li>
    /// </ul>
    /// This field is required.
    pub fn parameter_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.parameter_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Amazon Web Services PCS supports configuration of the following Slurm parameters:</p>
    /// <ul>
    /// <li>
    /// <p>For <b>clusters</b></p>
    /// <ul>
    /// <li>
    /// <p><a href="https://slurm.schedmd.com/slurm.conf.html#OPT_Prolog_1"> <code>Prolog</code> </a></p></li>
    /// <li>
    /// <p><a href="https://slurm.schedmd.com/slurm.conf.html#OPT_Epilog_1"> <code>Epilog</code> </a></p></li>
    /// <li>
    /// <p><a href="https://slurm.schedmd.com/slurm.conf.html#OPT_SelectTypeParameters"> <code>SelectTypeParameters</code> </a></p></li>
    /// </ul></li>
    /// <li>
    /// <p>For <b>compute node groups</b></p>
    /// <ul>
    /// <li>
    /// <p><a href="https://slurm.schedmd.com/slurm.conf.html#OPT_Weight"> <code>Weight</code> </a></p></li>
    /// <li>
    /// <p><a href="https://slurm.schedmd.com/slurm.conf.html#OPT_Weight"> <code>RealMemory</code> </a></p></li>
    /// </ul></li>
    /// </ul>
    pub fn set_parameter_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.parameter_name = input;
        self
    }
    /// <p>Amazon Web Services PCS supports configuration of the following Slurm parameters:</p>
    /// <ul>
    /// <li>
    /// <p>For <b>clusters</b></p>
    /// <ul>
    /// <li>
    /// <p><a href="https://slurm.schedmd.com/slurm.conf.html#OPT_Prolog_1"> <code>Prolog</code> </a></p></li>
    /// <li>
    /// <p><a href="https://slurm.schedmd.com/slurm.conf.html#OPT_Epilog_1"> <code>Epilog</code> </a></p></li>
    /// <li>
    /// <p><a href="https://slurm.schedmd.com/slurm.conf.html#OPT_SelectTypeParameters"> <code>SelectTypeParameters</code> </a></p></li>
    /// </ul></li>
    /// <li>
    /// <p>For <b>compute node groups</b></p>
    /// <ul>
    /// <li>
    /// <p><a href="https://slurm.schedmd.com/slurm.conf.html#OPT_Weight"> <code>Weight</code> </a></p></li>
    /// <li>
    /// <p><a href="https://slurm.schedmd.com/slurm.conf.html#OPT_Weight"> <code>RealMemory</code> </a></p></li>
    /// </ul></li>
    /// </ul>
    pub fn get_parameter_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.parameter_name
    }
    /// <p>The values for the configured Slurm settings.</p>
    /// This field is required.
    pub fn parameter_value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.parameter_value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The values for the configured Slurm settings.</p>
    pub fn set_parameter_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.parameter_value = input;
        self
    }
    /// <p>The values for the configured Slurm settings.</p>
    pub fn get_parameter_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.parameter_value
    }
    /// Consumes the builder and constructs a [`SlurmCustomSetting`](crate::types::SlurmCustomSetting).
    /// This method will fail if any of the following fields are not set:
    /// - [`parameter_name`](crate::types::builders::SlurmCustomSettingBuilder::parameter_name)
    /// - [`parameter_value`](crate::types::builders::SlurmCustomSettingBuilder::parameter_value)
    pub fn build(self) -> ::std::result::Result<crate::types::SlurmCustomSetting, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::SlurmCustomSetting {
            parameter_name: self.parameter_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "parameter_name",
                    "parameter_name was not specified but it is required when building SlurmCustomSetting",
                )
            })?,
            parameter_value: self.parameter_value.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "parameter_value",
                    "parameter_value was not specified but it is required when building SlurmCustomSetting",
                )
            })?,
        })
    }
}
