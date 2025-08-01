// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains details about the Lambda function containing the business logic that is carried out upon invoking the action or the custom control method for handling the information elicited from the user.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub enum ActionGroupExecutor {
    /// <p>To return the action group invocation results directly in the <code>InvokeAgent</code> response, specify <code>RETURN_CONTROL</code>.</p>
    CustomControl(crate::types::CustomControlMethod),
    /// <p>The Amazon Resource Name (ARN) of the Lambda function containing the business logic that is carried out upon invoking the action.</p>
    Lambda(::std::string::String),
    /// The `Unknown` variant represents cases where new union variant was received. Consider upgrading the SDK to the latest available version.
    /// An unknown enum variant
    ///
    /// _Note: If you encounter this error, consider upgrading your SDK to the latest version._
    /// The `Unknown` variant represents cases where the server sent a value that wasn't recognized
    /// by the client. This can happen when the server adds new functionality, but the client has not been updated.
    /// To investigate this, consider turning on debug logging to print the raw HTTP response.
    #[non_exhaustive]
    Unknown,
}
impl ActionGroupExecutor {
    /// Tries to convert the enum instance into [`CustomControl`](crate::types::ActionGroupExecutor::CustomControl), extracting the inner [`CustomControlMethod`](crate::types::CustomControlMethod).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_custom_control(&self) -> ::std::result::Result<&crate::types::CustomControlMethod, &Self> {
        if let ActionGroupExecutor::CustomControl(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`CustomControl`](crate::types::ActionGroupExecutor::CustomControl).
    pub fn is_custom_control(&self) -> bool {
        self.as_custom_control().is_ok()
    }
    /// Tries to convert the enum instance into [`Lambda`](crate::types::ActionGroupExecutor::Lambda), extracting the inner [`String`](::std::string::String).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_lambda(&self) -> ::std::result::Result<&::std::string::String, &Self> {
        if let ActionGroupExecutor::Lambda(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`Lambda`](crate::types::ActionGroupExecutor::Lambda).
    pub fn is_lambda(&self) -> bool {
        self.as_lambda().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
