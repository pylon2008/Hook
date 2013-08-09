// HookUIDlg.h : header file
//

#pragma once


// CHookUIDlg dialog
class CHookUIDlg : public CDialog
{
// Construction
public:
	CHookUIDlg(CWnd* pParent = NULL);	// standard constructor

// Dialog Data
	enum { IDD = IDD_HOOKUI_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support


// Implementation
protected:
	HICON m_hIcon;
	HMODULE m_hDLL;

	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedButtonInitHook();
	afx_msg void OnBnClickedButtonUninitHook();
private:
	CEdit m_editLocaltime;
public:
	afx_msg void OnBnClickedButtonGettime();
};
