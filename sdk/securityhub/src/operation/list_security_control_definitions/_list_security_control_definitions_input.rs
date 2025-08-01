// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListSecurityControlDefinitionsInput {
    /// <p>The Amazon Resource Name (ARN) of the standard that you want to view controls for.</p>
    pub standards_arn: ::std::option::Option<::std::string::String>,
    /// <p>Optional pagination parameter.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>An optional parameter that limits the total results of the API response to the specified number. If this parameter isn't provided in the request, the results include the first 25 security controls that apply to the specified standard. The results also include a <code>NextToken</code> parameter that you can use in a subsequent API call to get the next 25 controls. This repeats until all controls for the standard are returned.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListSecurityControlDefinitionsInput {
    /// <p>The Amazon Resource Name (ARN) of the standard that you want to view controls for.</p>
    pub fn standards_arn(&self) -> ::std::option::Option<&str> {
        self.standards_arn.as_deref()
    }
    /// <p>Optional pagination parameter.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>An optional parameter that limits the total results of the API response to the specified number. If this parameter isn't provided in the request, the results include the first 25 security controls that apply to the specified standard. The results also include a <code>NextToken</code> parameter that you can use in a subsequent API call to get the next 25 controls. This repeats until all controls for the standard are returned.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListSecurityControlDefinitionsInput {
    /// Creates a new builder-style object to manufacture [`ListSecurityControlDefinitionsInput`](crate::operation::list_security_control_definitions::ListSecurityControlDefinitionsInput).
    pub fn builder() -> crate::operation::list_security_control_definitions::builders::ListSecurityControlDefinitionsInputBuilder {
        crate::operation::list_security_control_definitions::builders::ListSecurityControlDefinitionsInputBuilder::default()
    }
}

/// A builder for [`ListSecurityControlDefinitionsInput`](crate::operation::list_security_control_definitions::ListSecurityControlDefinitionsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListSecurityControlDefinitionsInputBuilder {
    pub(crate) standards_arn: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListSecurityControlDefinitionsInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the standard that you want to view controls for.</p>
    pub fn standards_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.standards_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the standard that you want to view controls for.</p>
    pub fn set_standards_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.standards_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the standard that you want to view controls for.</p>
    pub fn get_standards_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.standards_arn
    }
    /// <p>Optional pagination parameter.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Optional pagination parameter.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>Optional pagination parameter.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>An optional parameter that limits the total results of the API response to the specified number. If this parameter isn't provided in the request, the results include the first 25 security controls that apply to the specified standard. The results also include a <code>NextToken</code> parameter that you can use in a subsequent API call to get the next 25 controls. This repeats until all controls for the standard are returned.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>An optional parameter that limits the total results of the API response to the specified number. If this parameter isn't provided in the request, the results include the first 25 security controls that apply to the specified standard. The results also include a <code>NextToken</code> parameter that you can use in a subsequent API call to get the next 25 controls. This repeats until all controls for the standard are returned.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>An optional parameter that limits the total results of the API response to the specified number. If this parameter isn't provided in the request, the results include the first 25 security controls that apply to the specified standard. The results also include a <code>NextToken</code> parameter that you can use in a subsequent API call to get the next 25 controls. This repeats until all controls for the standard are returned.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListSecurityControlDefinitionsInput`](crate::operation::list_security_control_definitions::ListSecurityControlDefinitionsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_security_control_definitions::ListSecurityControlDefinitionsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_security_control_definitions::ListSecurityControlDefinitionsInput {
            standards_arn: self.standards_arn,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
