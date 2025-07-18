// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The name of the step, used to identify the delete step.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteStepDetails {
    /// <p>The name of the step, used as an identifier.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>Specifies which file to use as input to the workflow step: either the output from the previous step, or the originally uploaded file for the workflow.</p>
    /// <ul>
    /// <li>
    /// <p>To use the previous file as the input, enter <code>${previous.file}</code>. In this case, this workflow step uses the output file from the previous workflow step as input. This is the default value.</p></li>
    /// <li>
    /// <p>To use the originally uploaded file location as input for this step, enter <code>${original.file}</code>.</p></li>
    /// </ul>
    pub source_file_location: ::std::option::Option<::std::string::String>,
}
impl DeleteStepDetails {
    /// <p>The name of the step, used as an identifier.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>Specifies which file to use as input to the workflow step: either the output from the previous step, or the originally uploaded file for the workflow.</p>
    /// <ul>
    /// <li>
    /// <p>To use the previous file as the input, enter <code>${previous.file}</code>. In this case, this workflow step uses the output file from the previous workflow step as input. This is the default value.</p></li>
    /// <li>
    /// <p>To use the originally uploaded file location as input for this step, enter <code>${original.file}</code>.</p></li>
    /// </ul>
    pub fn source_file_location(&self) -> ::std::option::Option<&str> {
        self.source_file_location.as_deref()
    }
}
impl DeleteStepDetails {
    /// Creates a new builder-style object to manufacture [`DeleteStepDetails`](crate::types::DeleteStepDetails).
    pub fn builder() -> crate::types::builders::DeleteStepDetailsBuilder {
        crate::types::builders::DeleteStepDetailsBuilder::default()
    }
}

/// A builder for [`DeleteStepDetails`](crate::types::DeleteStepDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteStepDetailsBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) source_file_location: ::std::option::Option<::std::string::String>,
}
impl DeleteStepDetailsBuilder {
    /// <p>The name of the step, used as an identifier.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the step, used as an identifier.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the step, used as an identifier.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>Specifies which file to use as input to the workflow step: either the output from the previous step, or the originally uploaded file for the workflow.</p>
    /// <ul>
    /// <li>
    /// <p>To use the previous file as the input, enter <code>${previous.file}</code>. In this case, this workflow step uses the output file from the previous workflow step as input. This is the default value.</p></li>
    /// <li>
    /// <p>To use the originally uploaded file location as input for this step, enter <code>${original.file}</code>.</p></li>
    /// </ul>
    pub fn source_file_location(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_file_location = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies which file to use as input to the workflow step: either the output from the previous step, or the originally uploaded file for the workflow.</p>
    /// <ul>
    /// <li>
    /// <p>To use the previous file as the input, enter <code>${previous.file}</code>. In this case, this workflow step uses the output file from the previous workflow step as input. This is the default value.</p></li>
    /// <li>
    /// <p>To use the originally uploaded file location as input for this step, enter <code>${original.file}</code>.</p></li>
    /// </ul>
    pub fn set_source_file_location(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_file_location = input;
        self
    }
    /// <p>Specifies which file to use as input to the workflow step: either the output from the previous step, or the originally uploaded file for the workflow.</p>
    /// <ul>
    /// <li>
    /// <p>To use the previous file as the input, enter <code>${previous.file}</code>. In this case, this workflow step uses the output file from the previous workflow step as input. This is the default value.</p></li>
    /// <li>
    /// <p>To use the originally uploaded file location as input for this step, enter <code>${original.file}</code>.</p></li>
    /// </ul>
    pub fn get_source_file_location(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_file_location
    }
    /// Consumes the builder and constructs a [`DeleteStepDetails`](crate::types::DeleteStepDetails).
    pub fn build(self) -> crate::types::DeleteStepDetails {
        crate::types::DeleteStepDetails {
            name: self.name,
            source_file_location: self.source_file_location,
        }
    }
}
