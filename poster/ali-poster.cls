\NeedsTeXFormat{LaTeX2e}
\ProvidesClass{ali-poster}
\LoadClass{article}

% -------------
% -- SPACING --
% -------------

\newlength{\marginwidth}
\setlength{\marginwidth}{2cm}

\RequirePackage[
	left=\marginwidth,
	right=\marginwidth,
	top = \marginwidth,
	bottom = 0cm,
	paperheight = 24in,
	paperwidth = 36in,
]{geometry}

\newlength{\footerheight}
\setlength{\footerheight}{\dimexpr.15\paperheight\relax}
\def\centerwidth{.72\paperwidth}

\RequirePackage{calc}
\def\sidebarwidth{\dimexpr
	\paperwidth-\centerwidth-\marginwidth-\marginwidth-\marginwidth
}

% -----------
% -- FONTS --
% -----------

\usepackage[
	fontsize=25pt,
]{fontsize}
\renewcommand{\familydefault}{\sfdefault}

\RequirePackage{parskip}

% ------------
% -- COLORS --
% ------------

\RequirePackage[dvipsnames]{xcolor}
\colorlet{highlightcolor1}{BrickRed}
\colorlet{highlightcolor2}{MidnightBlue}
\colorlet{footercolor}{MidnightBlue!70!white}
\colorlet{sidebarcolor}{MidnightBlue!20!white}

% -----------
% -- TITLE -- 
% -----------

\makeatletter
\def\@maketitle{
	\raggedright
	\textcolor{BrickRed}{\HUGE \bf \@title}

	\bigskip

	\@author
}
\makeatother

% --------------
% -- ABSTRACT --
% --------------

% TODO

% ------------
% -- FOOTER --
% ------------

% args: width, background color
% \newsavebox\panelbox%
% \newenvironment{panel}[2]
% {%
% 	\begin{lrbox}{\panelbox}
% 		\begin{minipage}[t]{#1}
% 			}{
% 		\end{minipage}%
% 	\end{lrbox}
% 	\colorbox{#2}{%
% 		\usebox{\panelbox}
% 	}
% }

\newenvironment{panel}[2]
{%
	\begin{minipage}[t]{#1}
		}{
	\end{minipage}%
}

\newcommand{\footer}[1]{
	\vspace*{\fill}
	\noindent\makebox[\linewidth][c]{%
		\colorbox{footercolor}{%
			\hspace{\marginwidth}
			\begin{minipage}[t][\footerheight][t]{\textwidth}
				\color{white}
				#1
			\end{minipage}
			\hspace{\marginwidth}
		}
		% \end{minipage}%
	}%
}