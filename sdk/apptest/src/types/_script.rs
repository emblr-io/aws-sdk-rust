// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the script.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Script {
    /// <p>The script location of the scripts.</p>
    pub script_location: ::std::string::String,
    /// <p>The type of the scripts.</p>
    pub r#type: crate::types::ScriptType,
}
impl Script {
    /// <p>The script location of the scripts.</p>
    pub fn script_location(&self) -> &str {
        use std::ops::Deref;
        self.script_location.deref()
    }
    /// <p>The type of the scripts.</p>
    pub fn r#type(&self) -> &crate::types::ScriptType {
        &self.r#type
    }
}
impl Script {
    /// Creates a new builder-style object to manufacture [`Script`](crate::types::Script).
    pub fn builder() -> crate::types::builders::ScriptBuilder {
        crate::types::builders::ScriptBuilder::default()
    }
}

/// A builder for [`Script`](crate::types::Script).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ScriptBuilder {
    pub(crate) script_location: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<crate::types::ScriptType>,
}
impl ScriptBuilder {
    /// <p>The script location of the scripts.</p>
    /// This field is required.
    pub fn script_location(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.script_location = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The script location of the scripts.</p>
    pub fn set_script_location(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.script_location = input;
        self
    }
    /// <p>The script location of the scripts.</p>
    pub fn get_script_location(&self) -> &::std::option::Option<::std::string::String> {
        &self.script_location
    }
    /// <p>The type of the scripts.</p>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::ScriptType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of the scripts.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::ScriptType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of the scripts.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::ScriptType> {
        &self.r#type
    }
    /// Consumes the builder and constructs a [`Script`](crate::types::Script).
    /// This method will fail if any of the following fields are not set:
    /// - [`script_location`](crate::types::builders::ScriptBuilder::script_location)
    /// - [`r#type`](crate::types::builders::ScriptBuilder::type)
    pub fn build(self) -> ::std::result::Result<crate::types::Script, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::Script {
            script_location: self.script_location.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "script_location",
                    "script_location was not specified but it is required when building Script",
                )
            })?,
            r#type: self.r#type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "r#type",
                    "r#type was not specified but it is required when building Script",
                )
            })?,
        })
    }
}
