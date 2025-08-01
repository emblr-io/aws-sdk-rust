// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The search input attribute value.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub enum SearchByAttributeValue {
    /// <p>The created at time of the image set provided for search.</p>
    CreatedAt(::aws_smithy_types::DateTime),
    /// <p>The DICOM accession number for search.</p>
    DicomAccessionNumber(::std::string::String),
    /// <p>The patient ID input for search.</p>
    DicomPatientId(::std::string::String),
    /// <p>The Series Instance UID input for search.</p>
    DicomSeriesInstanceUid(::std::string::String),
    /// <p>The aggregated structure containing DICOM study date and study time for search.</p>
    DicomStudyDateAndTime(crate::types::DicomStudyDateAndTime),
    /// <p>The DICOM study ID for search.</p>
    DicomStudyId(::std::string::String),
    /// <p>The DICOM study instance UID for search.</p>
    DicomStudyInstanceUid(::std::string::String),
    /// <p>The primary image set flag provided for search.</p>
    IsPrimary(bool),
    /// <p>The timestamp input for search.</p>
    UpdatedAt(::aws_smithy_types::DateTime),
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
impl SearchByAttributeValue {
    /// Tries to convert the enum instance into [`CreatedAt`](crate::types::SearchByAttributeValue::CreatedAt), extracting the inner [`DateTime`](::aws_smithy_types::DateTime).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_created_at(&self) -> ::std::result::Result<&::aws_smithy_types::DateTime, &Self> {
        if let SearchByAttributeValue::CreatedAt(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`CreatedAt`](crate::types::SearchByAttributeValue::CreatedAt).
    pub fn is_created_at(&self) -> bool {
        self.as_created_at().is_ok()
    }
    /// Tries to convert the enum instance into [`DicomAccessionNumber`](crate::types::SearchByAttributeValue::DicomAccessionNumber), extracting the inner [`String`](::std::string::String).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_dicom_accession_number(&self) -> ::std::result::Result<&::std::string::String, &Self> {
        if let SearchByAttributeValue::DicomAccessionNumber(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`DicomAccessionNumber`](crate::types::SearchByAttributeValue::DicomAccessionNumber).
    pub fn is_dicom_accession_number(&self) -> bool {
        self.as_dicom_accession_number().is_ok()
    }
    /// Tries to convert the enum instance into [`DicomPatientId`](crate::types::SearchByAttributeValue::DicomPatientId), extracting the inner [`String`](::std::string::String).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_dicom_patient_id(&self) -> ::std::result::Result<&::std::string::String, &Self> {
        if let SearchByAttributeValue::DicomPatientId(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`DicomPatientId`](crate::types::SearchByAttributeValue::DicomPatientId).
    pub fn is_dicom_patient_id(&self) -> bool {
        self.as_dicom_patient_id().is_ok()
    }
    /// Tries to convert the enum instance into [`DicomSeriesInstanceUid`](crate::types::SearchByAttributeValue::DicomSeriesInstanceUid), extracting the inner [`String`](::std::string::String).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_dicom_series_instance_uid(&self) -> ::std::result::Result<&::std::string::String, &Self> {
        if let SearchByAttributeValue::DicomSeriesInstanceUid(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`DicomSeriesInstanceUid`](crate::types::SearchByAttributeValue::DicomSeriesInstanceUid).
    pub fn is_dicom_series_instance_uid(&self) -> bool {
        self.as_dicom_series_instance_uid().is_ok()
    }
    /// Tries to convert the enum instance into [`DicomStudyDateAndTime`](crate::types::SearchByAttributeValue::DicomStudyDateAndTime), extracting the inner [`DicomStudyDateAndTime`](crate::types::DicomStudyDateAndTime).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_dicom_study_date_and_time(&self) -> ::std::result::Result<&crate::types::DicomStudyDateAndTime, &Self> {
        if let SearchByAttributeValue::DicomStudyDateAndTime(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`DicomStudyDateAndTime`](crate::types::SearchByAttributeValue::DicomStudyDateAndTime).
    pub fn is_dicom_study_date_and_time(&self) -> bool {
        self.as_dicom_study_date_and_time().is_ok()
    }
    /// Tries to convert the enum instance into [`DicomStudyId`](crate::types::SearchByAttributeValue::DicomStudyId), extracting the inner [`String`](::std::string::String).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_dicom_study_id(&self) -> ::std::result::Result<&::std::string::String, &Self> {
        if let SearchByAttributeValue::DicomStudyId(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`DicomStudyId`](crate::types::SearchByAttributeValue::DicomStudyId).
    pub fn is_dicom_study_id(&self) -> bool {
        self.as_dicom_study_id().is_ok()
    }
    /// Tries to convert the enum instance into [`DicomStudyInstanceUid`](crate::types::SearchByAttributeValue::DicomStudyInstanceUid), extracting the inner [`String`](::std::string::String).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_dicom_study_instance_uid(&self) -> ::std::result::Result<&::std::string::String, &Self> {
        if let SearchByAttributeValue::DicomStudyInstanceUid(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`DicomStudyInstanceUid`](crate::types::SearchByAttributeValue::DicomStudyInstanceUid).
    pub fn is_dicom_study_instance_uid(&self) -> bool {
        self.as_dicom_study_instance_uid().is_ok()
    }
    /// Tries to convert the enum instance into [`IsPrimary`](crate::types::SearchByAttributeValue::IsPrimary), extracting the inner [`bool`](bool).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_is_primary(&self) -> ::std::result::Result<&bool, &Self> {
        if let SearchByAttributeValue::IsPrimary(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`IsPrimary`](crate::types::SearchByAttributeValue::IsPrimary).
    pub fn is_is_primary(&self) -> bool {
        self.as_is_primary().is_ok()
    }
    /// Tries to convert the enum instance into [`UpdatedAt`](crate::types::SearchByAttributeValue::UpdatedAt), extracting the inner [`DateTime`](::aws_smithy_types::DateTime).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_updated_at(&self) -> ::std::result::Result<&::aws_smithy_types::DateTime, &Self> {
        if let SearchByAttributeValue::UpdatedAt(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`UpdatedAt`](crate::types::SearchByAttributeValue::UpdatedAt).
    pub fn is_updated_at(&self) -> bool {
        self.as_updated_at().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
impl ::std::fmt::Debug for SearchByAttributeValue {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match self {
            SearchByAttributeValue::CreatedAt(val) => f.debug_tuple("CreatedAt").field(&val).finish(),
            SearchByAttributeValue::DicomAccessionNumber(_) => f.debug_tuple("*** Sensitive Data Redacted ***").finish(),
            SearchByAttributeValue::DicomPatientId(_) => f.debug_tuple("*** Sensitive Data Redacted ***").finish(),
            SearchByAttributeValue::DicomSeriesInstanceUid(_) => f.debug_tuple("*** Sensitive Data Redacted ***").finish(),
            SearchByAttributeValue::DicomStudyDateAndTime(val) => f.debug_tuple("DicomStudyDateAndTime").field(&val).finish(),
            SearchByAttributeValue::DicomStudyId(_) => f.debug_tuple("*** Sensitive Data Redacted ***").finish(),
            SearchByAttributeValue::DicomStudyInstanceUid(_) => f.debug_tuple("*** Sensitive Data Redacted ***").finish(),
            SearchByAttributeValue::IsPrimary(val) => f.debug_tuple("IsPrimary").field(&val).finish(),
            SearchByAttributeValue::UpdatedAt(val) => f.debug_tuple("UpdatedAt").field(&val).finish(),
            SearchByAttributeValue::Unknown => f.debug_tuple("Unknown").finish(),
        }
    }
}
