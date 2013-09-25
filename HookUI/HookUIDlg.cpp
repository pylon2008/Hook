// HookUIDlg.cpp : implementation file
//

#include "stdafx.h"
#include "HookUI.h"
#include "HookUIDlg.h"
//#include "../HookDll/HookDll.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CAboutDlg dialog used for App About

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// Dialog Data
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

// Implementation
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
END_MESSAGE_MAP()


// CHookUIDlg dialog




CHookUIDlg::CHookUIDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CHookUIDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	m_hDLL = 0;
}

void CHookUIDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT_LOCALTIME, m_editLocaltime);
}

BEGIN_MESSAGE_MAP(CHookUIDlg, CDialog)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	//}}AFX_MSG_MAP
	ON_BN_CLICKED(IDC_BUTTON_INIT_HOOK, &CHookUIDlg::OnBnClickedButtonInitHook)
	ON_BN_CLICKED(IDC_BUTTON_UNINIT_HOOK, &CHookUIDlg::OnBnClickedButtonUninitHook)
	ON_BN_CLICKED(IDC_BUTTON_GETTIME, &CHookUIDlg::OnBnClickedButtonGettime)
END_MESSAGE_MAP()


// CHookUIDlg message handlers

BOOL CHookUIDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		CString strAboutMenu;
		strAboutMenu.LoadString(IDS_ABOUTBOX);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	// TODO: Add extra initialization here

	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CHookUIDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CHookUIDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CHookUIDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void CHookUIDlg::OnBnClickedButtonInitHook()
{
	// TODO: Add your control notification handler code here
	//InitHook();

	if (m_hDLL == 0)
	{
		m_hDLL = ::LoadLibrary(_T("D:\\WorkStation\\Git\\Hub\\Hook\\bin\\HookDll"));       //º”‘ÿDLL
	}
	if (m_hDLL!=NULL)
	{
		typedef void (*LOADHOOK)(HWND hwnd);
		LOADHOOK loadhook=(LOADHOOK)::GetProcAddress (m_hDLL,"In");
		loadhook(m_hWnd);
	}
}

void CHookUIDlg::OnBnClickedButtonUninitHook()
{
	// TODO: Add your control notification handler code here
	//UnInitHook();
	if (m_hDLL == 0)
	{
		m_hDLL = ::LoadLibrary(_T("HookDllS"));       //º”‘ÿDLL
	}
	if (m_hDLL!=NULL)
	{
		typedef void (*LOADHOOK)();
		LOADHOOK loadhook=(LOADHOOK)::GetProcAddress (m_hDLL,"UnInitHook");
		loadhook();
		::FreeLibrary(m_hDLL);
		m_hDLL = 0;
	}
}

void CHookUIDlg::OnBnClickedButtonGettime()
{
	// TODO: Add your control notification handler code here
	SYSTEMTIME time;
	::GetLocalTime(&time);
	wchar_t buf[1024] = {0};
	swprintf(buf, L"%d-%d-%d-%d-%d-%d-%d-%d", time.wYear, time.wMonth, time.wDay, time.wDayOfWeek, time.wHour, time.wMinute, time.wMinute, time.wMilliseconds);
	::MessageBox(0, buf, 0, 0);
}
