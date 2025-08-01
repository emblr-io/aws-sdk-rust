// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetSensitiveDataOccurrencesAvailabilityOutput {
    /// <p>Specifies whether occurrences of sensitive data can be retrieved for the finding. Possible values are: AVAILABLE, the sensitive data can be retrieved; and, UNAVAILABLE, the sensitive data can't be retrieved. If this value is UNAVAILABLE, the reasons array indicates why the data can't be retrieved.</p>
    pub code: ::std::option::Option<crate::types::AvailabilityCode>,
    /// <p>Specifies why occurrences of sensitive data can't be retrieved for the finding. Possible values are:</p>
    /// <ul>
    /// <li>
    /// <p>ACCOUNT_NOT_IN_ORGANIZATION - The affected account isn't currently part of your organization. Or the account is part of your organization but Macie isn't currently enabled for the account. You're not allowed to access the affected S3 object by using Macie.</p></li>
    /// <li>
    /// <p>INVALID_CLASSIFICATION_RESULT - There isn't a corresponding sensitive data discovery result for the finding. Or the corresponding sensitive data discovery result isn't available in the current Amazon Web Services Region, is malformed or corrupted, or uses an unsupported storage format. Macie can't verify the location of the sensitive data to retrieve.</p></li>
    /// <li>
    /// <p>INVALID_RESULT_SIGNATURE - The corresponding sensitive data discovery result is stored in an S3 object that wasn't signed by Macie. Macie can't verify the integrity and authenticity of the sensitive data discovery result. Therefore, Macie can't verify the location of the sensitive data to retrieve.</p></li>
    /// <li>
    /// <p>MEMBER_ROLE_TOO_PERMISSIVE - The trust or permissions policy for the IAM role in the affected member account doesn't meet Macie requirements for restricting access to the role. Or the role's trust policy doesn't specify the correct external ID for your organization. Macie can't assume the role to retrieve the sensitive data.</p></li>
    /// <li>
    /// <p>MISSING_GET_MEMBER_PERMISSION - You're not allowed to retrieve information about the association between your account and the affected account. Macie can't determine whether you’re allowed to access the affected S3 object as the delegated Macie administrator for the affected account.</p></li>
    /// <li>
    /// <p>OBJECT_EXCEEDS_SIZE_QUOTA - The storage size of the affected S3 object exceeds the size quota for retrieving occurrences of sensitive data from this type of file.</p></li>
    /// <li>
    /// <p>OBJECT_UNAVAILABLE - The affected S3 object isn't available. The object was renamed, moved, deleted, or changed after Macie created the finding. Or the object is encrypted with an KMS key that isn’t available. For example, the key is disabled, is scheduled for deletion, or was deleted.</p></li>
    /// <li>
    /// <p>RESULT_NOT_SIGNED - The corresponding sensitive data discovery result is stored in an S3 object that hasn't been signed. Macie can't verify the integrity and authenticity of the sensitive data discovery result. Therefore, Macie can't verify the location of the sensitive data to retrieve.</p></li>
    /// <li>
    /// <p>ROLE_TOO_PERMISSIVE - Your account is configured to retrieve occurrences of sensitive data by using an IAM role whose trust or permissions policy doesn't meet Macie requirements for restricting access to the role. Macie can’t assume the role to retrieve the sensitive data.</p></li>
    /// <li>
    /// <p>UNSUPPORTED_FINDING_TYPE - The specified finding isn't a sensitive data finding.</p></li>
    /// <li>
    /// <p>UNSUPPORTED_OBJECT_TYPE - The affected S3 object uses a file or storage format that Macie doesn't support for retrieving occurrences of sensitive data.</p></li>
    /// </ul>
    /// <p>This value is null if sensitive data can be retrieved for the finding.</p>
    pub reasons: ::std::option::Option<::std::vec::Vec<crate::types::UnavailabilityReasonCode>>,
    _request_id: Option<String>,
}
impl GetSensitiveDataOccurrencesAvailabilityOutput {
    /// <p>Specifies whether occurrences of sensitive data can be retrieved for the finding. Possible values are: AVAILABLE, the sensitive data can be retrieved; and, UNAVAILABLE, the sensitive data can't be retrieved. If this value is UNAVAILABLE, the reasons array indicates why the data can't be retrieved.</p>
    pub fn code(&self) -> ::std::option::Option<&crate::types::AvailabilityCode> {
        self.code.as_ref()
    }
    /// <p>Specifies why occurrences of sensitive data can't be retrieved for the finding. Possible values are:</p>
    /// <ul>
    /// <li>
    /// <p>ACCOUNT_NOT_IN_ORGANIZATION - The affected account isn't currently part of your organization. Or the account is part of your organization but Macie isn't currently enabled for the account. You're not allowed to access the affected S3 object by using Macie.</p></li>
    /// <li>
    /// <p>INVALID_CLASSIFICATION_RESULT - There isn't a corresponding sensitive data discovery result for the finding. Or the corresponding sensitive data discovery result isn't available in the current Amazon Web Services Region, is malformed or corrupted, or uses an unsupported storage format. Macie can't verify the location of the sensitive data to retrieve.</p></li>
    /// <li>
    /// <p>INVALID_RESULT_SIGNATURE - The corresponding sensitive data discovery result is stored in an S3 object that wasn't signed by Macie. Macie can't verify the integrity and authenticity of the sensitive data discovery result. Therefore, Macie can't verify the location of the sensitive data to retrieve.</p></li>
    /// <li>
    /// <p>MEMBER_ROLE_TOO_PERMISSIVE - The trust or permissions policy for the IAM role in the affected member account doesn't meet Macie requirements for restricting access to the role. Or the role's trust policy doesn't specify the correct external ID for your organization. Macie can't assume the role to retrieve the sensitive data.</p></li>
    /// <li>
    /// <p>MISSING_GET_MEMBER_PERMISSION - You're not allowed to retrieve information about the association between your account and the affected account. Macie can't determine whether you’re allowed to access the affected S3 object as the delegated Macie administrator for the affected account.</p></li>
    /// <li>
    /// <p>OBJECT_EXCEEDS_SIZE_QUOTA - The storage size of the affected S3 object exceeds the size quota for retrieving occurrences of sensitive data from this type of file.</p></li>
    /// <li>
    /// <p>OBJECT_UNAVAILABLE - The affected S3 object isn't available. The object was renamed, moved, deleted, or changed after Macie created the finding. Or the object is encrypted with an KMS key that isn’t available. For example, the key is disabled, is scheduled for deletion, or was deleted.</p></li>
    /// <li>
    /// <p>RESULT_NOT_SIGNED - The corresponding sensitive data discovery result is stored in an S3 object that hasn't been signed. Macie can't verify the integrity and authenticity of the sensitive data discovery result. Therefore, Macie can't verify the location of the sensitive data to retrieve.</p></li>
    /// <li>
    /// <p>ROLE_TOO_PERMISSIVE - Your account is configured to retrieve occurrences of sensitive data by using an IAM role whose trust or permissions policy doesn't meet Macie requirements for restricting access to the role. Macie can’t assume the role to retrieve the sensitive data.</p></li>
    /// <li>
    /// <p>UNSUPPORTED_FINDING_TYPE - The specified finding isn't a sensitive data finding.</p></li>
    /// <li>
    /// <p>UNSUPPORTED_OBJECT_TYPE - The affected S3 object uses a file or storage format that Macie doesn't support for retrieving occurrences of sensitive data.</p></li>
    /// </ul>
    /// <p>This value is null if sensitive data can be retrieved for the finding.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.reasons.is_none()`.
    pub fn reasons(&self) -> &[crate::types::UnavailabilityReasonCode] {
        self.reasons.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for GetSensitiveDataOccurrencesAvailabilityOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetSensitiveDataOccurrencesAvailabilityOutput {
    /// Creates a new builder-style object to manufacture [`GetSensitiveDataOccurrencesAvailabilityOutput`](crate::operation::get_sensitive_data_occurrences_availability::GetSensitiveDataOccurrencesAvailabilityOutput).
    pub fn builder() -> crate::operation::get_sensitive_data_occurrences_availability::builders::GetSensitiveDataOccurrencesAvailabilityOutputBuilder
    {
        crate::operation::get_sensitive_data_occurrences_availability::builders::GetSensitiveDataOccurrencesAvailabilityOutputBuilder::default()
    }
}

/// A builder for [`GetSensitiveDataOccurrencesAvailabilityOutput`](crate::operation::get_sensitive_data_occurrences_availability::GetSensitiveDataOccurrencesAvailabilityOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetSensitiveDataOccurrencesAvailabilityOutputBuilder {
    pub(crate) code: ::std::option::Option<crate::types::AvailabilityCode>,
    pub(crate) reasons: ::std::option::Option<::std::vec::Vec<crate::types::UnavailabilityReasonCode>>,
    _request_id: Option<String>,
}
impl GetSensitiveDataOccurrencesAvailabilityOutputBuilder {
    /// <p>Specifies whether occurrences of sensitive data can be retrieved for the finding. Possible values are: AVAILABLE, the sensitive data can be retrieved; and, UNAVAILABLE, the sensitive data can't be retrieved. If this value is UNAVAILABLE, the reasons array indicates why the data can't be retrieved.</p>
    pub fn code(mut self, input: crate::types::AvailabilityCode) -> Self {
        self.code = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether occurrences of sensitive data can be retrieved for the finding. Possible values are: AVAILABLE, the sensitive data can be retrieved; and, UNAVAILABLE, the sensitive data can't be retrieved. If this value is UNAVAILABLE, the reasons array indicates why the data can't be retrieved.</p>
    pub fn set_code(mut self, input: ::std::option::Option<crate::types::AvailabilityCode>) -> Self {
        self.code = input;
        self
    }
    /// <p>Specifies whether occurrences of sensitive data can be retrieved for the finding. Possible values are: AVAILABLE, the sensitive data can be retrieved; and, UNAVAILABLE, the sensitive data can't be retrieved. If this value is UNAVAILABLE, the reasons array indicates why the data can't be retrieved.</p>
    pub fn get_code(&self) -> &::std::option::Option<crate::types::AvailabilityCode> {
        &self.code
    }
    /// Appends an item to `reasons`.
    ///
    /// To override the contents of this collection use [`set_reasons`](Self::set_reasons).
    ///
    /// <p>Specifies why occurrences of sensitive data can't be retrieved for the finding. Possible values are:</p>
    /// <ul>
    /// <li>
    /// <p>ACCOUNT_NOT_IN_ORGANIZATION - The affected account isn't currently part of your organization. Or the account is part of your organization but Macie isn't currently enabled for the account. You're not allowed to access the affected S3 object by using Macie.</p></li>
    /// <li>
    /// <p>INVALID_CLASSIFICATION_RESULT - There isn't a corresponding sensitive data discovery result for the finding. Or the corresponding sensitive data discovery result isn't available in the current Amazon Web Services Region, is malformed or corrupted, or uses an unsupported storage format. Macie can't verify the location of the sensitive data to retrieve.</p></li>
    /// <li>
    /// <p>INVALID_RESULT_SIGNATURE - The corresponding sensitive data discovery result is stored in an S3 object that wasn't signed by Macie. Macie can't verify the integrity and authenticity of the sensitive data discovery result. Therefore, Macie can't verify the location of the sensitive data to retrieve.</p></li>
    /// <li>
    /// <p>MEMBER_ROLE_TOO_PERMISSIVE - The trust or permissions policy for the IAM role in the affected member account doesn't meet Macie requirements for restricting access to the role. Or the role's trust policy doesn't specify the correct external ID for your organization. Macie can't assume the role to retrieve the sensitive data.</p></li>
    /// <li>
    /// <p>MISSING_GET_MEMBER_PERMISSION - You're not allowed to retrieve information about the association between your account and the affected account. Macie can't determine whether you’re allowed to access the affected S3 object as the delegated Macie administrator for the affected account.</p></li>
    /// <li>
    /// <p>OBJECT_EXCEEDS_SIZE_QUOTA - The storage size of the affected S3 object exceeds the size quota for retrieving occurrences of sensitive data from this type of file.</p></li>
    /// <li>
    /// <p>OBJECT_UNAVAILABLE - The affected S3 object isn't available. The object was renamed, moved, deleted, or changed after Macie created the finding. Or the object is encrypted with an KMS key that isn’t available. For example, the key is disabled, is scheduled for deletion, or was deleted.</p></li>
    /// <li>
    /// <p>RESULT_NOT_SIGNED - The corresponding sensitive data discovery result is stored in an S3 object that hasn't been signed. Macie can't verify the integrity and authenticity of the sensitive data discovery result. Therefore, Macie can't verify the location of the sensitive data to retrieve.</p></li>
    /// <li>
    /// <p>ROLE_TOO_PERMISSIVE - Your account is configured to retrieve occurrences of sensitive data by using an IAM role whose trust or permissions policy doesn't meet Macie requirements for restricting access to the role. Macie can’t assume the role to retrieve the sensitive data.</p></li>
    /// <li>
    /// <p>UNSUPPORTED_FINDING_TYPE - The specified finding isn't a sensitive data finding.</p></li>
    /// <li>
    /// <p>UNSUPPORTED_OBJECT_TYPE - The affected S3 object uses a file or storage format that Macie doesn't support for retrieving occurrences of sensitive data.</p></li>
    /// </ul>
    /// <p>This value is null if sensitive data can be retrieved for the finding.</p>
    pub fn reasons(mut self, input: crate::types::UnavailabilityReasonCode) -> Self {
        let mut v = self.reasons.unwrap_or_default();
        v.push(input);
        self.reasons = ::std::option::Option::Some(v);
        self
    }
    /// <p>Specifies why occurrences of sensitive data can't be retrieved for the finding. Possible values are:</p>
    /// <ul>
    /// <li>
    /// <p>ACCOUNT_NOT_IN_ORGANIZATION - The affected account isn't currently part of your organization. Or the account is part of your organization but Macie isn't currently enabled for the account. You're not allowed to access the affected S3 object by using Macie.</p></li>
    /// <li>
    /// <p>INVALID_CLASSIFICATION_RESULT - There isn't a corresponding sensitive data discovery result for the finding. Or the corresponding sensitive data discovery result isn't available in the current Amazon Web Services Region, is malformed or corrupted, or uses an unsupported storage format. Macie can't verify the location of the sensitive data to retrieve.</p></li>
    /// <li>
    /// <p>INVALID_RESULT_SIGNATURE - The corresponding sensitive data discovery result is stored in an S3 object that wasn't signed by Macie. Macie can't verify the integrity and authenticity of the sensitive data discovery result. Therefore, Macie can't verify the location of the sensitive data to retrieve.</p></li>
    /// <li>
    /// <p>MEMBER_ROLE_TOO_PERMISSIVE - The trust or permissions policy for the IAM role in the affected member account doesn't meet Macie requirements for restricting access to the role. Or the role's trust policy doesn't specify the correct external ID for your organization. Macie can't assume the role to retrieve the sensitive data.</p></li>
    /// <li>
    /// <p>MISSING_GET_MEMBER_PERMISSION - You're not allowed to retrieve information about the association between your account and the affected account. Macie can't determine whether you’re allowed to access the affected S3 object as the delegated Macie administrator for the affected account.</p></li>
    /// <li>
    /// <p>OBJECT_EXCEEDS_SIZE_QUOTA - The storage size of the affected S3 object exceeds the size quota for retrieving occurrences of sensitive data from this type of file.</p></li>
    /// <li>
    /// <p>OBJECT_UNAVAILABLE - The affected S3 object isn't available. The object was renamed, moved, deleted, or changed after Macie created the finding. Or the object is encrypted with an KMS key that isn’t available. For example, the key is disabled, is scheduled for deletion, or was deleted.</p></li>
    /// <li>
    /// <p>RESULT_NOT_SIGNED - The corresponding sensitive data discovery result is stored in an S3 object that hasn't been signed. Macie can't verify the integrity and authenticity of the sensitive data discovery result. Therefore, Macie can't verify the location of the sensitive data to retrieve.</p></li>
    /// <li>
    /// <p>ROLE_TOO_PERMISSIVE - Your account is configured to retrieve occurrences of sensitive data by using an IAM role whose trust or permissions policy doesn't meet Macie requirements for restricting access to the role. Macie can’t assume the role to retrieve the sensitive data.</p></li>
    /// <li>
    /// <p>UNSUPPORTED_FINDING_TYPE - The specified finding isn't a sensitive data finding.</p></li>
    /// <li>
    /// <p>UNSUPPORTED_OBJECT_TYPE - The affected S3 object uses a file or storage format that Macie doesn't support for retrieving occurrences of sensitive data.</p></li>
    /// </ul>
    /// <p>This value is null if sensitive data can be retrieved for the finding.</p>
    pub fn set_reasons(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::UnavailabilityReasonCode>>) -> Self {
        self.reasons = input;
        self
    }
    /// <p>Specifies why occurrences of sensitive data can't be retrieved for the finding. Possible values are:</p>
    /// <ul>
    /// <li>
    /// <p>ACCOUNT_NOT_IN_ORGANIZATION - The affected account isn't currently part of your organization. Or the account is part of your organization but Macie isn't currently enabled for the account. You're not allowed to access the affected S3 object by using Macie.</p></li>
    /// <li>
    /// <p>INVALID_CLASSIFICATION_RESULT - There isn't a corresponding sensitive data discovery result for the finding. Or the corresponding sensitive data discovery result isn't available in the current Amazon Web Services Region, is malformed or corrupted, or uses an unsupported storage format. Macie can't verify the location of the sensitive data to retrieve.</p></li>
    /// <li>
    /// <p>INVALID_RESULT_SIGNATURE - The corresponding sensitive data discovery result is stored in an S3 object that wasn't signed by Macie. Macie can't verify the integrity and authenticity of the sensitive data discovery result. Therefore, Macie can't verify the location of the sensitive data to retrieve.</p></li>
    /// <li>
    /// <p>MEMBER_ROLE_TOO_PERMISSIVE - The trust or permissions policy for the IAM role in the affected member account doesn't meet Macie requirements for restricting access to the role. Or the role's trust policy doesn't specify the correct external ID for your organization. Macie can't assume the role to retrieve the sensitive data.</p></li>
    /// <li>
    /// <p>MISSING_GET_MEMBER_PERMISSION - You're not allowed to retrieve information about the association between your account and the affected account. Macie can't determine whether you’re allowed to access the affected S3 object as the delegated Macie administrator for the affected account.</p></li>
    /// <li>
    /// <p>OBJECT_EXCEEDS_SIZE_QUOTA - The storage size of the affected S3 object exceeds the size quota for retrieving occurrences of sensitive data from this type of file.</p></li>
    /// <li>
    /// <p>OBJECT_UNAVAILABLE - The affected S3 object isn't available. The object was renamed, moved, deleted, or changed after Macie created the finding. Or the object is encrypted with an KMS key that isn’t available. For example, the key is disabled, is scheduled for deletion, or was deleted.</p></li>
    /// <li>
    /// <p>RESULT_NOT_SIGNED - The corresponding sensitive data discovery result is stored in an S3 object that hasn't been signed. Macie can't verify the integrity and authenticity of the sensitive data discovery result. Therefore, Macie can't verify the location of the sensitive data to retrieve.</p></li>
    /// <li>
    /// <p>ROLE_TOO_PERMISSIVE - Your account is configured to retrieve occurrences of sensitive data by using an IAM role whose trust or permissions policy doesn't meet Macie requirements for restricting access to the role. Macie can’t assume the role to retrieve the sensitive data.</p></li>
    /// <li>
    /// <p>UNSUPPORTED_FINDING_TYPE - The specified finding isn't a sensitive data finding.</p></li>
    /// <li>
    /// <p>UNSUPPORTED_OBJECT_TYPE - The affected S3 object uses a file or storage format that Macie doesn't support for retrieving occurrences of sensitive data.</p></li>
    /// </ul>
    /// <p>This value is null if sensitive data can be retrieved for the finding.</p>
    pub fn get_reasons(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::UnavailabilityReasonCode>> {
        &self.reasons
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetSensitiveDataOccurrencesAvailabilityOutput`](crate::operation::get_sensitive_data_occurrences_availability::GetSensitiveDataOccurrencesAvailabilityOutput).
    pub fn build(self) -> crate::operation::get_sensitive_data_occurrences_availability::GetSensitiveDataOccurrencesAvailabilityOutput {
        crate::operation::get_sensitive_data_occurrences_availability::GetSensitiveDataOccurrencesAvailabilityOutput {
            code: self.code,
            reasons: self.reasons,
            _request_id: self._request_id,
        }
    }
}
