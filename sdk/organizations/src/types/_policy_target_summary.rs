// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about a root, OU, or account that a policy is attached to.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PolicyTargetSummary {
    /// <p>The unique identifier (ID) of the policy target.</p>
    /// <p>The <a href="http://wikipedia.org/wiki/regex">regex pattern</a> for a target ID string requires one of the following:</p>
    /// <ul>
    /// <li>
    /// <p><b>Root</b> - A string that begins with "r-" followed by from 4 to 32 lowercase letters or digits.</p></li>
    /// <li>
    /// <p><b>Account</b> - A string that consists of exactly 12 digits.</p></li>
    /// <li>
    /// <p><b>Organizational unit (OU)</b> - A string that begins with "ou-" followed by from 4 to 32 lowercase letters or digits (the ID of the root that the OU is in). This string is followed by a second "-" dash and from 8 to 32 additional lowercase letters or digits.</p></li>
    /// </ul>
    pub target_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the policy target.</p>
    /// <p>For more information about ARNs in Organizations, see <a href="https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsorganizations.html#awsorganizations-resources-for-iam-policies">ARN Formats Supported by Organizations</a> in the <i>Amazon Web Services Service Authorization Reference</i>.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The friendly name of the policy target.</p>
    /// <p>The <a href="http://wikipedia.org/wiki/regex">regex pattern</a> that is used to validate this parameter is a string of any of the characters in the ASCII character range.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The type of the policy target.</p>
    pub r#type: ::std::option::Option<crate::types::TargetType>,
}
impl PolicyTargetSummary {
    /// <p>The unique identifier (ID) of the policy target.</p>
    /// <p>The <a href="http://wikipedia.org/wiki/regex">regex pattern</a> for a target ID string requires one of the following:</p>
    /// <ul>
    /// <li>
    /// <p><b>Root</b> - A string that begins with "r-" followed by from 4 to 32 lowercase letters or digits.</p></li>
    /// <li>
    /// <p><b>Account</b> - A string that consists of exactly 12 digits.</p></li>
    /// <li>
    /// <p><b>Organizational unit (OU)</b> - A string that begins with "ou-" followed by from 4 to 32 lowercase letters or digits (the ID of the root that the OU is in). This string is followed by a second "-" dash and from 8 to 32 additional lowercase letters or digits.</p></li>
    /// </ul>
    pub fn target_id(&self) -> ::std::option::Option<&str> {
        self.target_id.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the policy target.</p>
    /// <p>For more information about ARNs in Organizations, see <a href="https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsorganizations.html#awsorganizations-resources-for-iam-policies">ARN Formats Supported by Organizations</a> in the <i>Amazon Web Services Service Authorization Reference</i>.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The friendly name of the policy target.</p>
    /// <p>The <a href="http://wikipedia.org/wiki/regex">regex pattern</a> that is used to validate this parameter is a string of any of the characters in the ASCII character range.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The type of the policy target.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::TargetType> {
        self.r#type.as_ref()
    }
}
impl PolicyTargetSummary {
    /// Creates a new builder-style object to manufacture [`PolicyTargetSummary`](crate::types::PolicyTargetSummary).
    pub fn builder() -> crate::types::builders::PolicyTargetSummaryBuilder {
        crate::types::builders::PolicyTargetSummaryBuilder::default()
    }
}

/// A builder for [`PolicyTargetSummary`](crate::types::PolicyTargetSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PolicyTargetSummaryBuilder {
    pub(crate) target_id: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<crate::types::TargetType>,
}
impl PolicyTargetSummaryBuilder {
    /// <p>The unique identifier (ID) of the policy target.</p>
    /// <p>The <a href="http://wikipedia.org/wiki/regex">regex pattern</a> for a target ID string requires one of the following:</p>
    /// <ul>
    /// <li>
    /// <p><b>Root</b> - A string that begins with "r-" followed by from 4 to 32 lowercase letters or digits.</p></li>
    /// <li>
    /// <p><b>Account</b> - A string that consists of exactly 12 digits.</p></li>
    /// <li>
    /// <p><b>Organizational unit (OU)</b> - A string that begins with "ou-" followed by from 4 to 32 lowercase letters or digits (the ID of the root that the OU is in). This string is followed by a second "-" dash and from 8 to 32 additional lowercase letters or digits.</p></li>
    /// </ul>
    pub fn target_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.target_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier (ID) of the policy target.</p>
    /// <p>The <a href="http://wikipedia.org/wiki/regex">regex pattern</a> for a target ID string requires one of the following:</p>
    /// <ul>
    /// <li>
    /// <p><b>Root</b> - A string that begins with "r-" followed by from 4 to 32 lowercase letters or digits.</p></li>
    /// <li>
    /// <p><b>Account</b> - A string that consists of exactly 12 digits.</p></li>
    /// <li>
    /// <p><b>Organizational unit (OU)</b> - A string that begins with "ou-" followed by from 4 to 32 lowercase letters or digits (the ID of the root that the OU is in). This string is followed by a second "-" dash and from 8 to 32 additional lowercase letters or digits.</p></li>
    /// </ul>
    pub fn set_target_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.target_id = input;
        self
    }
    /// <p>The unique identifier (ID) of the policy target.</p>
    /// <p>The <a href="http://wikipedia.org/wiki/regex">regex pattern</a> for a target ID string requires one of the following:</p>
    /// <ul>
    /// <li>
    /// <p><b>Root</b> - A string that begins with "r-" followed by from 4 to 32 lowercase letters or digits.</p></li>
    /// <li>
    /// <p><b>Account</b> - A string that consists of exactly 12 digits.</p></li>
    /// <li>
    /// <p><b>Organizational unit (OU)</b> - A string that begins with "ou-" followed by from 4 to 32 lowercase letters or digits (the ID of the root that the OU is in). This string is followed by a second "-" dash and from 8 to 32 additional lowercase letters or digits.</p></li>
    /// </ul>
    pub fn get_target_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.target_id
    }
    /// <p>The Amazon Resource Name (ARN) of the policy target.</p>
    /// <p>For more information about ARNs in Organizations, see <a href="https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsorganizations.html#awsorganizations-resources-for-iam-policies">ARN Formats Supported by Organizations</a> in the <i>Amazon Web Services Service Authorization Reference</i>.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the policy target.</p>
    /// <p>For more information about ARNs in Organizations, see <a href="https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsorganizations.html#awsorganizations-resources-for-iam-policies">ARN Formats Supported by Organizations</a> in the <i>Amazon Web Services Service Authorization Reference</i>.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the policy target.</p>
    /// <p>For more information about ARNs in Organizations, see <a href="https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsorganizations.html#awsorganizations-resources-for-iam-policies">ARN Formats Supported by Organizations</a> in the <i>Amazon Web Services Service Authorization Reference</i>.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The friendly name of the policy target.</p>
    /// <p>The <a href="http://wikipedia.org/wiki/regex">regex pattern</a> that is used to validate this parameter is a string of any of the characters in the ASCII character range.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The friendly name of the policy target.</p>
    /// <p>The <a href="http://wikipedia.org/wiki/regex">regex pattern</a> that is used to validate this parameter is a string of any of the characters in the ASCII character range.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The friendly name of the policy target.</p>
    /// <p>The <a href="http://wikipedia.org/wiki/regex">regex pattern</a> that is used to validate this parameter is a string of any of the characters in the ASCII character range.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The type of the policy target.</p>
    pub fn r#type(mut self, input: crate::types::TargetType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of the policy target.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::TargetType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of the policy target.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::TargetType> {
        &self.r#type
    }
    /// Consumes the builder and constructs a [`PolicyTargetSummary`](crate::types::PolicyTargetSummary).
    pub fn build(self) -> crate::types::PolicyTargetSummary {
        crate::types::PolicyTargetSummary {
            target_id: self.target_id,
            arn: self.arn,
            name: self.name,
            r#type: self.r#type,
        }
    }
}
